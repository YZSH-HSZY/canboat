import socket

if __name__ == "__main__":
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("0.0.0.0", 9999))
    while True:
        data, addr = s.recvfrom(9999)
        print(data.hex(), ";", data.decode("utf-8", "ignore"), ";", addr)
