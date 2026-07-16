from .read_file import read_file
from .map_share import share_paths
from .verbosity_logging import logger
from impacket.smbconnection import SMBConnection

def run(session: SMBConnection, share_name: str, full_path: str, local_path: str) -> None:
    for share, file_paths in share_paths.items():
        if share.name == share_name and full_path in file_paths[0]:
            remote_path, content = read_file(session=session, share=share, full_path=full_path)
    
    new_file: str = local_path
    
    try:
        with open(new_file, "w") as f:
            f.write(content.decode())
            logger.warning(f"Successfully downloaded {remote_path} from {share.name} ==> {local_path}")
    except Exception as e:
        logger.error(f"Unhandled error while downloading {remote_path} from {share.name} to {local_path}: {e}")