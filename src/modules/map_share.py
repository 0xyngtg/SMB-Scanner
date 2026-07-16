import json
from typing import Any

from .verbosity_logging import logger
from .connect import Share
from impacket.smbconnection import SMBConnection, SessionError
from impacket.smb import SharedFile

type FullPath = str
type FileSize = int
type ModTime = bytes
type FilePaths = list[tuple[FullPath, FileSize, ModTime]]

share_paths: dict[Share, FilePaths] = {}

def list_path(session: SMBConnection, share: Share, output=False) -> FilePaths:
    """
    Creates a list of all files in the given share by recursively traversing the directory.
    Returns a list of tuples containing the file path, file size, and file's last modified time.
    Has option to output the list of files to the logger.
    """
    
    file_paths: FilePaths = []
    stack: list[str] = ["*"]
    
    while stack:
        path = stack.pop()
        
        try:
            files: list[SharedFile] = session.listPath(shareName=share.name, path=path)
            for f in files:
                if f.get_longname() in [".", ".."]:
                    continue
                if f.is_directory():
                    stack.append(path.replace("*", "") + f.get_longname() + "/*")
                else:
                    fullpath: str = path.replace("*", "") + f.get_longname()
                    file_paths.append(
                        (fullpath, f.get_filesize(), f.get_mtime())
                    )
            
            if output:
                logger.info(f"Files in \"{share.name}/{path}\":\n" + "\n".join(f"({'DIR' if f.is_directory() else 'FILE'}) {f.get_longname()}" for f in files))
        
        except SessionError as e:
            logger.error(f"Path {share.name}/{path} was not found: {e}")
        except Exception:
            logger.error(f"Unhandled error mapping {share.name}/{path}")
    
    return file_paths

def load_file(file) -> dict:
    with open(file, 'r') as f:
        return json.loads(f.read())

def run(session: SMBConnection, shares_info: list[Share], file: str):
    global share_paths
    
    output_data: dict[str, Any] = {}
    
    if file:
        map_data = load_file(file)
        
        for share_name, share_info in map_data.items():
            metadata = share_info["metadata"]
            share = Share(
                name=metadata["Name"],
                type=metadata["Type"],
                remark=metadata["Remark"],
                permission=metadata["Permission"],
                treeID=metadata["TreeID"]
            )
            share_paths[share] = share_info["Files"]
            
    else:
        for share in shares_info:
            if share.permission.get("READ", False):
                file_paths: FilePaths = list_path(session=session, share=share) # output False
                
                output_data[share.name] = {
                    "metadata": {
                        "Name": share.name,
                        "Type": share.type,
                        "Remark": share.remark,
                        "Permission": share.permission,
                        "TreeID": share.treeID
                    },
                    "Files": file_paths
                }
                
                share_paths[share] = file_paths
                
        with open('map.json', 'w') as f:
            json.dump(output_data, f, indent=2)
