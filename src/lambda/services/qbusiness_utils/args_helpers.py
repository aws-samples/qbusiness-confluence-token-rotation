
import argparse
import base64

def get_refresher_parsed_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--secret_name', dest='secret_name', type=str, help='Add secret_name (configured in your Qbusiness application Confluence datasource)')
    parser.add_argument('--backup_secret_name', dest='backup_secret_name', type=str, help='Add backup_secret_name (backup secret where confluence credentials for the refresh token script are saved)')
    return parser.parse_args()

def validate_args(parsed_args, op):
    if op == 'refresh':
        if not parsed_args.secret_name:
            raise Exception("secret_name is required")
        if not parsed_args.backup_secret_name:
            raise Exception("backup_secret_name is required")