from .connect import Share
from .verbosity_logging import logger
from .map_share import share_paths
from impacket.smbconnection import SMBConnection, FILE_SHARE_WRITE

def get_data(local_file_path: str) -> bytes:
    "Reads the local file and returns its content as bytes"
    with open(local_file_path, 'r') as f:
        return f.read().encode()

def exists(file_path: str, share_name: str) -> bool:
    "Checks if the given file exits on a specific share"
    found: bool = False
    for share, file_paths in share_paths.items():
        if share_name == share.name:
            if file_path in file_paths:
                found = True
    return found

def write_file(session: SMBConnection, content: bytes, file_path: str, share: Share) -> int | None:
    """Creates a new file on the given share and writes the content"""
    try:
        logger.debug(f'Creating file {share}/{file_path}')
        treeID = session.connectTree(share.name)
        fileID = session.createFile(treeId=treeID, pathName=file_path, shareMode=FILE_SHARE_WRITE)
        result = session.writeFile(treeId=treeID, fileId=fileID, data=content)
        logger.info(f'{result} bytes were written to {file_path}!')
        return result
    except Exception as e:
        logger.error(f'Unexpected error writing data to {file_path}: {e}')

def overwrite_file(session: SMBConnection, content: bytes, file_path: str, share: Share) -> int | None:
    """Overwrites a given file"""
    try:
        logger.debug(f'Overwritting file {share.name}/{file_path}')
        fileID = session.createFile(treeId=share.treeID, pathName=file_path, shareMode=FILE_SHARE_WRITE)
        result = session.writeFile(treeId=share.treeID, fileId=fileID, data=content)
        logger.info(f'{result} bytes were written to {file_path}!')
        return result
    except Exception as e:
        logger.error(f'Unexpected error writing data to {file_path}: {e}')


def run(session: SMBConnection, local_file_path: str, share_name: str, remote_file_path: str) -> None:
    content: bytes = get_data(local_file_path)
    
    for share, file_paths in share_paths.items():
        if share_name == share.name and remote_file_path in file_paths[0]:
            overwrite_file(session=session, content=content, file_path=remote_file_path, share=share)
        else:
            write_file(session=session, content=content, file_path=remote_file_path, share=share)
                