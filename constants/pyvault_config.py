# CONSTANTS. Linux environment.
from pathlib import Path

HOME = str(Path.home())

# change filenames here.
SEAL_PATH = HOME + "/seal"
KEY_FILE_NAME = "mykey.key"
SEAL_FILE_NAME = "seal"
TOKEN_FILE_NAME = "token"

# ABSOLUTE PATHS OF THE FILES.
SEAL_FILE_PATH = SEAL_PATH + "/" + SEAL_FILE_NAME
TOKEN_FILE_PATH = SEAL_PATH + "/" + TOKEN_FILE_NAME
KEY_FILE_PATH = SEAL_PATH + "/" + KEY_FILE_NAME

# CHANGE SERVER AND PORT INFORMATION HERE.
VAULT_PORT = "8200"
VAULT_IP_ADDRESS = "192.168.1.50"
VAULT_ADDRESS = f"https://{VAULT_IP_ADDRESS}:{VAULT_PORT}"

# VAULT INIT
VAULT_INIT = "/v1/sys/init"

# VAULT MOUNT POINT
VAULT_MNT = "/v1/sys/mounts/"

# USE PUT TO SEAL VAULT
VAULT_SEAL = "/v1/sys/seal"

# GET SEAL STATUS
VAULT_SEAL_STATUS = "/v1/sys/seal-status"

# PUT UNSEAL VAULT, ONE KEY PER CALL
VAULT_UNSEAL = "/v1/sys/unseal"

# CREATE TOKEN URI
CREATE_TOKEN = "/v1/auth/token/create"
