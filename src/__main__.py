import argparse

from .modules.verbosity_logging import logger, run as verbosity_logging_main
from .modules.connect import run as connect_main
from .modules.map_share import run as map_share_main, share_paths
from .modules.hunter import run as hunter_run
from .modules.read_file import read_file
from .modules.write_file import run as write_file_run
from .modules.download import run as download_file_run

def arguments() -> argparse.Namespace:
    """Parses command-line arguments and returns them as a Namespace object."""
    parser= argparse.ArgumentParser(prog="smbscanner.py", description="A simple tool that connects to a SMB server and magically finds credentials!", add_help= True)
    parser.add_argument("-t", "--target", default=None, required=True, help="Target IP address or hostname")
    parser.add_argument("-u", "--user", default=None, required=False,help="Username")
    parser.add_argument("-p", "--password", default=None, required=False, help="Password")
    parser.add_argument("-d", "--domain", default="", required=False, help="Domain")
    parser.add_argument("-H", "--hashes", default=None, required=False, help="LM:NT hashes")
    parser.add_argument("-s", "--share", default=None, required=False, help="Share to connect to")
    parser.add_argument("-v", "--verbose", default=False, required=False, action="store_true", help= "Adds verbosity level")
    parser.add_argument("--path", default=None, required=False, help="Base Path relative to the given share! SPECIFY THE TARGET SHARE WITH '-s <SHARE>'")
    parser.add_argument("--scan", default=False, required=False, action="store_true", help= "Turns on the scan mode, which will read all files on the Share and find patterns that potentially represent sensitive information")
    parser.add_argument("--recursive", default=False, required=False, action="store_true", help= "Turns on recursive mode! RECOMMENDED TO SPECIFY THE TARGET SHARE WITH '-s <SHARE>'")
    parser.add_argument("--regex", default="", required=False, help= "Uses a custom regex pattern to scan for secrets (ONLY ONE REGEX PATTERN)")
    parser.add_argument("--log", default=None, required=False, help="Log File Name")
    parser.add_argument("--port", type=int, default=445, required=False, help="Port to connect to")
    parser.add_argument("--read", type=str, required=False, help="Reads a specific file. Required to provide the -s <SHARE> option.")
    parser.add_argument("--write", type=str, required=False, nargs=2, help="Writes to a specific file. Requires 2 arguments: <LOCAL-FILE> <REMOTE-FILE>. Required to provide the -s <SHARE> option.")
    parser.add_argument("--download", type=str, required=False, nargs=2, help="Downloads a remote file. Requires 2 arguments: <REMOTE-FILE> <LOCAL-FILE>. Required to provide the -s <SHARE> option.")
    parser.add_argument("--map", default="",type=str, required=False, help="After the first run the script will output a JSON file containing the share map. This file can be loaded to avoid remapping the share once again.")

    return parser.parse_args()

def main():
    args : argparse.Namespace= arguments()
    
    verbosity_logging_main(log_file=args.log, verbosity_option=args.verbose)
    
    session, shares_info = connect_main(args=args) # SMBConnection, list[Share]
    
    map_share_main(session=session, shares_info=shares_info, file=args.map) # dict[str, FilePaths]
    
    if args.scan: # --scan => --recursive | --regex | --share | --path options (hunter.py module)
        if args.recursive and not args.share and not args.path: # Scan all files in all shares
            hunter_run(session, recursive=True, regex=args.regex)
        elif args.recursive and args.share and not args.path: # Scan a specific share recursively
            hunter_run(session, recursive=True, share_name=args.share, regex=args.regex)
        elif args.share and args.path and not args.recursive: # Scan a specific file in the given share
            hunter_run(session, recursive=False, share_name=args.share, path=args.path, regex=args.regex)
        else:
            logger.error("Bad scanning options. Try: --scan -s <SHARE> --recursive")
    elif args.read and args.share and args.path: # --read - read module
        for share_item in share_paths.items():
            share, file_paths = share_item
            if args.share == share.name and args.path in file_paths:
                file_path, content = read_file(session=session, share=share, full_path=args.path)
                logger.warning(f"File: {file_path}\nContent:\n{content}")
            else:
                logger.error(f"{args.path} was not found. Check the given file path")
    
    elif args.write and args.share: # --write - write module
        write_file_run(session=session, local_file_path=args.write[0], share_name=args.share, remote_file_path=args.write[1])
    
    elif args.download and args.share: # --download - download module
        download_file_run(session=session, share_name=args.share, full_path=args.download[0], local_path=args.download[1])
    
    

if __name__ == "__main__":
    main()
