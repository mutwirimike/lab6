import requests
import hashlib
import subprocess
import os

def main():

    # Get the expected SHA-256 hash value of the VLC installer
    expected_sha256 = get_expected_sha256()

    # Download (but don't save) the VLC installer from the VLC website
    installer_data = download_installer()

    # Verify the integrity of the downloaded VLC installer by comparing the
    # expected and computed SHA-256 hash values
    if installer_ok(installer_data, expected_sha256):

        # Save the downloaded VLC installer to disk
        installer_path = save_installer(installer_data)

        # Silently run the VLC installer
        run_installer(installer_path)

        # Delete the VLC installer from disk
        delete_installer(installer_path)

def get_expected_sha256():
    """Downloads the text file containing the expected SHA-256 value for the VLC installer file from the 
    videolan.org website and extracts the expected SHA-256 value from it.

    Returns:
        str: Expected SHA-256 hash value of VLC installer
    """
    # TODO: Step 1
    # Hint: See example code in lab instructions entitled "Extracting Text from a Response Message Body"
    # Hint: Use str class methods, str slicing, and/or regex to extract the expected SHA-256 value from the text 

    # Send GET message to download the file
    file_url = 'https://download.videolan.org/pub/videolan/vlc/3.0.17.4/win64/vlc-3.0.17.4-win64.exe.sha256'
    resp_msg = requests.get(file_url)
    # Check whether the download was successful
    if resp_msg.status_code == requests.codes.ok:
        # Extract text file content from response message
        file_content = resp_msg.text
        # Save the text file to disk
        with open(r'C:\temp\sha_code.txt', 'w') as file:
            file.write(file_content)
        sha = file_content.split(' ')
        shacode = sha[0]
    return shacode

def download_installer():
    """Downloads, but does not save, the .exe VLC installer file for 64-bit Windows.

    Returns:
        bytes: VLC installer file binary data
    """
    # TODO: Step 2
    # Hint: See example code in lab instructions entitled "Downloading a Binary File"

    # Send GET message to download the file
    file_url = 'https://download.videolan.org/pub/videolan/vlc/3.0.17.4/win64/vlc-3.0.17.4-win64.exe'
    resp_msg = requests.get(file_url)
    # Check whether the download was successful
    if resp_msg.status_code == requests.codes.ok:
        # Extract binary file content from response message
        file_content = resp_msg.content
    return file_content

def installer_ok(installer_data, expected_sha256):
    """Verifies the integrity of the downloaded VLC installer file by calculating its SHA-256 hash value 
    and comparing it against the expected SHA-256 hash value. 

    Args:
        installer_data (bytes): VLC installer file binary data
        expected_sha256 (str): Expeced SHA-256 of the VLC installer

    Returns:
        bool: True if SHA-256 of VLC installer matches expected SHA-256. False if not.
    """    
    # TODO: Step 3
    # Hint: See example code in lab instructions entitled "Computing the Hash Value of a Response Message Body"
    # Calculate SHA-256 hash value
    installer_hash = hashlib.sha256(installer_data).hexdigest()
    if expected_sha256 == installer_hash:
        return True
    else:
        return False

def save_installer(installer_data):
    """Saves the VLC installer to a local directory.

    Args:
        installer_data (bytes): VLC installer file binary data

    Returns:
        str: Full path of the saved VLC installer file
    """
    # TODO: Step 4
    # Hint: See example code in lab instructions entitled "Downloading a Binary File"
    download_path = r'C:\temp\vlc.exe'
    # Save the binary file to disk
    with open(download_path, 'wb') as file:
        file.write(installer_data)    
    return download_path

def run_installer(installer_path):
    """Silently runs the VLC installer.

    Args:
        installer_path (str): Full path of the VLC installer file
    """    
    # TODO: Step 5
    # Hint: See example code in lab instructions entitled "Running the VLC Installer"
    
    #used shell as it was showing error for asking admin privilages
    subprocess.run([installer_path, '/L=1033', '/S'], shell=True)
    return
    
def delete_installer(installer_path):
    # TODO: Step 6
    # Hint: See example code in lab instructions entitled "Running the VLC Installer"
    """Deletes the VLC installer file.

    Args:
        installer_path (str): Full path of the VLC installer file
    """
    os.remove(installer_path)
    return

if __name__ == '__main__':
    main()