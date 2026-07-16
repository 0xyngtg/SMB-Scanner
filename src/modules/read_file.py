from .connect import Share
from .verbosity_logging import logger
from impacket.smbconnection import SMBConnection, FILE_READ_DATA

def read_file(session:SMBConnection, share: Share, full_path:str) -> tuple[str,bytes]:
    """Reads a specific file and returns its path and content"""
    desiredAccess = FILE_READ_DATA
    try:
        fileID : bytes | None = session.openFile(
            share.treeID,
            pathName=full_path,
            desiredAccess=desiredAccess
        )
        
        #file_info : SMBQueryFileBasicInfo | None = session.queryInfo(treeID, fileID)
        #file_size : int | None = file_info['EndOfFile']
        
        data : bytes = session.readFile(share.treeID, fileID, offset=0, bytesToRead=None)
        #logger.debug(f'{path} content:\n{data}')
        
        return full_path, data
    except Exception as e:
        logger.error(f'Unexpected error reading {share.treeID} | {share.name}: {full_path} - {e}')
        return ("", b"")
