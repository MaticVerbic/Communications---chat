import socket
import struct
import sys
import threading
import json
import datetime

PORT = 1234
HEADER_LENGTH = 2


def receive_fixed_length_msg(sock, msglen):
    message = b''
    while len(message) < msglen:
        chunk = sock.recv(msglen - len(message))  # preberi nekaj bajtov
        if chunk == b'':
            raise RuntimeError("socket connection broken")
        message = message + chunk  # pripni prebrane bajte sporocilu

    return message


def receive_message(sock):
    header = receive_fixed_length_msg(sock,
                                      HEADER_LENGTH)  # preberi glavo sporocila (v prvih 2 bytih je dolzina sporocila)
    message_length = struct.unpack("!H", header)[0]  # pretvori dolzino sporocila v int

    message = None
    if message_length > 0:  # ce je vse OK
        message = receive_fixed_length_msg(sock, message_length)  # preberi sporocilo
        message = message.decode("utf-8")

    return message


def send_message(sock, message):
    encoded_message = message.encode("utf-8")  # pretvori sporocilo v niz bajtov, uporabi UTF-8 kodno tabelo

    # ustvari glavo v prvih 2 bytih je dolzina sporocila (HEADER_LENGTH)
    # metoda pack "!H" : !=network byte order, H=unsigned short
    header = struct.pack("!H", len(encoded_message))

    message = header + encoded_message  # najprj posljemo dolzino sporocilo, slee nato sporocilo samo
    sock.sendall(message);


# message_receiver funkcija tece v loceni niti
def message_receiver():
    while True:
        msg_received = receive_message(sock)
        if len(msg_received) > 0:
            try:
                data = json.loads(msg_received)
                if "terminate" in data.keys() and data["terminate"]:
                    print(data["message"])
                    sys.exit()
                elif "terminate" in data.keys() and not data["terminate"]:
                    print(data["message"])
                    continue
                if data["private"]:
                    msg = "Direct message: " + data["username"] + " at " \
                          + data["time"].split(" ")[1][:-3] + " says: " + data["message"]
                else:
                    msg = "Global chat: " + data["username"] + " at " \
                         + data["time"].split(" ")[1][:-3] + " says: " + data["message"]# izpisi
                print(msg)
            except Exception as e:
                #print(e)
                pass



# povezi se na streznik
print("[system] connecting to chat server ...")
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(("localhost", PORT))
print("[system] connected!")
#getUsername
username = input("Input your username: ")
# zazeni message_receiver funkcijo v loceni niti
thread = threading.Thread(target=message_receiver)
thread.daemon = True
thread.start()

greeter = {
    "username": username,
    "greeting": True
}

try:
    send_message(sock, json.dumps(greeter))

except Exception as e:
    #print(e)
    pass

# pocakaj da uporabnik nekaj natipka in poslji na streznik
while True:
    try:
        msg_send = input("")
        if "!u" in msg_send:
            msg_split = msg_send.split(" ")
            recepient = msg_split[1]
            msg = " ".join(msg_split[2:])
            mkjson = {
                "username": username,
                "message": msg,
                "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "destination": recepient,
                "private": True,
                "greeting": False
            }
        else:
            mkjson = {
                "username": username,
                "message": msg_send,
                "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "destination": False,
                "private": False,
                "greeting": False
            }
        send_message(sock, json.dumps(mkjson))
    except KeyboardInterrupt:
        sys.exit()
