from argparse import Namespace
from dataclasses import dataclass

from .verbosity_logging import logger
from impacket.smbconnection import SMBConnection, SessionError

def connect(config: LoginConfig) -> SMBConnection:
    """Connects to the target SMB Server and returns the SMBConnection object."""
    try:
        logger.debug(f"Connecting to {config.name} on port {config.port}...")
        session= SMBConnection(
            remoteName=config.name, 
            remoteHost=config.host, 
            sess_port=config.port
            )
        return session
    except SessionError as e:
        logger.error(f"Error during connection: {e}")

def auth_password(session: SMBConnection, config: LoginConfig) -> None:
    """Authenticates to the target SMB Server using the provided password."""
    try:
        logger.debug(f"Authenticating with password to {config.name} on port {config.port} with {config.domain}/{config.username}:********...")
        session.login(
            user=config.username, 
            password=config.password, 
            domain=config.domain
            )
    except SessionError as e:
        logger.error(f"Error during authentication: {e}")

def auth_hash(session: SMBConnection, config: LoginConfig) -> None:
    """Authenticates to the target SMB Server using the provided hashes."""
    try:
        logger.debug(f"Authenticating with hashes to {config.name} on port {config.port} with {config.domain}/{config.username}:********:********...")
        session.login(
            user=config.username, 
            password='', 
            domain=config.domain, 
            lmhash=config.hashes[0], 
            nthash=config.hashes[1]
            )
    
    except SessionError as e:
        logger.error(f"Error during authentication: {e}")

def auth_kerberos(session: SMBConnection, config: LoginConfig) -> None:
    """Authenticates to the target SMB Server using Kerberos."""
    ...

@dataclass
class LoginConfig:
    domain : str
    name : str
    host : str
    username : str
    password : str
    hash : str
    port : int = 445

    @property
    def hashes(self) -> tuple:
        if self.hash:
            lm, nt= self.hash.split(":")
            return lm, nt
        else:
            return None

def list_shares(session: SMBConnection) -> list[Share]:
    """
    Lists the shares available on the target SMB server.
    This function calls the get_treeid, and set_permissions methods and tests for permissions..
    It also logs the server information and returns a list of Share objects.
    """
    shares_info : list[Share] = []
    try:
        shares : dict = session.listShares()
        
        for x in shares:
            share : Share = Share(
                name = x["shi1_netname"][:-1],
                type = x["shi1_type"],
                remark = x["shi1_remark"][:-1] if x["shi1_remark"] else "",
                permission = None,
                treeID = None
            )
            share.permission = share.set_permissions(session)
            share.treeID = share.get_treeid(session)
            shares_info.append(share)
    
    except Exception as e:
        logger.error(f"Unhandled error listing the shares: {e}")
    
    logger.warning(f"Server info:\nOS: {session.getServerOS()}\nDomain: {session.getServerDomain()}")
    logger.warning(f"Listed shares:\n{'\n'.join(str(share.name + "  |  " + "Permissions: " + str(share.permission) + "  |  " + "Description: " + share.remark) for share in shares_info)}")
    return shares_info

class Share():
    def __init__(self, name: str, type: str, remark: str, permission: dict[str, bool] | None, treeID: int | None):
        self.name = name
        self.type = type
        self.remark = remark
        self.permission = permission
        self.treeID = treeID
    
    def get_read_permissions(self, session: SMBConnection, path:str="*") -> bool:
        """
        Checks if the current session has read permissions by attempting to list the files in the share.
        Returns True if successful, False otherwise.
        """
        read_perm = False
        try:
            logger.debug(f'Trying to read {self.name}...')
            session.listPath(self.name, path)
            read_perm = True
        except SessionError as e:
            pass
        except Exception as e:
            logger.error(f"Unhandled error trying to read {self.name}: {e}")
        return read_perm

    def get_write_permissions(self, session: SMBConnection, path:str="temp") -> bool:
        """
        Checks if the current session has write permissions by attempting to create a temporary file. This file is deleted immediately.
        Returns True if successful, False otherwise.
        """
        write_perm = False
        try:
            logger.debug(f"Trying to write \"{path}\" to {self.name}...")
            session.createDirectory(self.name, path)
            write_perm = True
            logger.debug(f"Trying to delete \"{path}\" to {self.name}...")
            session.deleteDirectory(self.name, path)
        except SessionError:
            return write_perm
        except Exception as e:
            logger.error(f"Unhandled error trying to write to {self.name}: {e}")
        return write_perm

    def set_permissions(self, session: SMBConnection) -> dict[str,bool]:
        """Sets the permissions for the share and modifies the permission attribute."""
        self.permission = {"READ" : self.get_read_permissions(session), "WRITE" : self.get_write_permissions(session)}
        return self.permission

    def get_treeid(self, session: SMBConnection) -> int | None:
        """Gets the tree ID for the share and modifies the treeID attribute."""
        try:
            self.treeID = session.connectTree(self.name)
            #session.disconnectTree(self.treeID)
        except SessionError as e:
            pass
        except Exception as e:
            logger.error(f"Unhandled error connecting to the share {self.name}: {e}")
        return self.treeID

def run(args: Namespace) -> tuple[SMBConnection, list[Share]]:
    login_config : LoginConfig= LoginConfig(
        domain=args.domain,
        name=args.target,
        host=args.target,
        port=args.port,
        username=args.user,
        password=args.password,
        hash= args.hashes
    )
    
    session: SMBConnection = connect(config=login_config)
    if login_config.hashes:
        auth_hash(session=session, config=login_config)
    elif login_config.password:
        auth_password(session=session, config=login_config)
    shares_info: list[Share] = list_shares(session=session)
    
    return session, shares_info
