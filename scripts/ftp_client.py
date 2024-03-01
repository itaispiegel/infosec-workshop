import time
from ftplib import FTP

SERVER_IP = "10.1.2.2"
credentials = ("fw", "fw")


def print_and_sleep(line):
    print(line)
    # time.sleep(30)


def main():
    with FTP(SERVER_IP) as ftp:
        ftp.set_pasv(False)
        ftp.login(*credentials)
        ftp.retrlines("LIST /etc", callback=print_and_sleep)


if __name__ == "__main__":
    main()
