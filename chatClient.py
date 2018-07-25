import socket
import struct
import sys
import threading
import json
import datetime

import traceback

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

                elif "friendlist" in data.keys() and "friendlistReply" in data.keys() and data["friendlist"] and data["friendlistReply"]:
                    msg = data["message"]
                    print(msg)
                    continue

                if "group" in data.keys() and data["group"]:
                    print(data["message"])
                    continue

                if "private_disabled" in data.keys() and data["private_disabled"]:
                    print(data["message"])
                    continue

                if "private" in data.keys() and data["private"]:
                    msg = "Direct message: " + data["username"] + " at " \
                          + data["time"].split(" ")[1][:-3] + " says: " + data["message"]

                    print(msg)
                elif "private" in data.keys() and not data["private"]:

                    msg = "Global chat: " + data["username"] + " at " \
                         + data["time"].split(" ")[1][:-3] + " says: " + data["message"]# izpisi

                    print(msg)
                else:
                    continue
            except Exception as e:
                traceback.print_exc()
                #print(e)
                pass



# povezi se na streznik
print("[system] connecting to chat server ...")
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(("localhost", PORT))
print("[system] connected!")

#getUsername
username = input("Input your username: ")
print("")
# zazeni message_receiver funkcijo v loceni niti
thread = threading.Thread(target=message_receiver)
thread.daemon = True
thread.start()

greeter = {
    "username": username,
    "greeting": True
}

help = "\n\n#############################################################################################################\n" \
       "#\t HELP                                                                                                   #\n" \
       "#\tFor a public message simply input the message                                                           #\n" \
       "#\tFor a private message enter '!u <username> <message>'                                                   #\n" \
       "#\tTo add a user to your friendlist enter '!f add <username>'                                              #\n" \
       "#\tTo remove a user from your friendlist enter'!f del <username>                                           #\n" \
       "#\tTo enable private private messaging enter '!f enable'                                                   #\n" \
       "#\tTo disable private private messaging enter '!f disable'                                                 #\n" \
       "#\tTo create a group enter '!g create <groupname>'                                                         #\n" \
       "#\tTo add members to a group enter '!g add <groupname> [username]' \\separate usernames with a space (' ')' #\n" \
       "#\tTo remove members from a group enter '!g del <groupname> [username]'                                    #\n" \
       "#\tTo send a message to a group enter '!g send <groupname> <message>'                                      #\n" \
       "#\tFor help enter '!h' or '!help'                                                                          #\n" \
       "#############################################################################################################\n\n"

print("for help enter !h or !help")

try:
    send_message(sock, json.dumps(greeter))

except Exception as e:
    #print(e)
    pass

# pocakaj da uporabnik nekaj natipka in poslji na streznik
while True:
    try:
        msg_send = input("")
        if msg_send == "!h" or msg_send == "!help":
            print(help)
            continue
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
                "greeting": False,
                "group": False
            }
        elif "!f" in msg_send:
            mkjson = {
                "username": username,
                "message": msg_send,
                "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "friendlist": True,
                "greeting": False
            }
        elif "!g" in msg_send:
            mkjson = {}
            if "!g create" in msg_send:
                groupname = msg_send.split(" ")[2]
                msg = " ".join(msg_send.split(" ")[:2])

                mkjson = {
                    "username": username,
                    "message": msg_send,
                    "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "greeting": False,
                    "group": True,
                    "group_settings": True,
                    "groupname": groupname

                }
            elif "!g add" in msg_send or "!g del" in msg_send:
                users = [user for user in msg_send.split(" ")[3:]]
                groupname = msg_send.split(" ")[2]
                msg = " ".join(msg_send.split(" ")[:2])

                mkjson = {
                    "username": username,
                    "message": msg_send,
                    "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "greeting": False,
                    "group": True,
                    "group_settings": True,
                    "groupname": groupname,
                    "users": users

                }
            elif "!g send" == msg_send[:7]:
                groupname = msg_send.split(" ")[2]
                mkjson = {
                    "username": username,
                    "message": msg_send,
                    "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "greeting": False,
                    "group": True,
                    "group_settings": False,
                    "group_message": True,
                    "groupname": groupname
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
