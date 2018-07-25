import signal
import json
import traceback

signal.signal(signal.SIGINT, signal.SIG_DFL)
import socket
import struct
import threading

PORT = 1234
HEADER_LENGTH = 2



'''
Vse dodatne funkcije


OCENJEVALCI RK: 
Za onemočanje dodatnih funkcionalnost zakomentirajte funkcije group_settings, group_messages in friendlist. 
Zakomentirajte tudi njihovo uporabo v funkciji client_thread(). 


'''


def group_settings(client_sock, data):
    if "group" in data.keys() and "group_settings" in data.keys() and data["group"] and data["group_settings"]:
        if "!g create" in data["message"]:
            mkjson = {
                "message": "",
                "group_created": False,
                "group": True

            }
            if data["groupname"] not in groups:
                groups[data["groupname"]] = {
                    "members": [data["username"]],
                    "admin": data["username"]
                }
                mkjson["message"] = "[system] Group successfully created."
                mkjson["group_created"] = True
                send_message(client_sock, json.dumps(mkjson))
                return True
            else:
                mkjson["message"] ="[system] Group name already exists"
                send_message(client_sock, json.dumps(mkjson))
                return True
        if "groupname" in data.keys() and data["groupname"] in groups \
                and groups[data["groupname"]]["admin"] != data["username"]:
            mkjson = {
                "message": "[System] Only group admin can add/remove members from group",
                "group": True,
                "notAdmin": True
            }
            send_message(client_sock, json.dumps(mkjson))
            return False
        if "!g add" in data["message"]:
            mkjson = {
                "message": "",
                "groupAdd": False,
                "group": True
            }
            messageS = ""
            messageF = ""
            if "groupname" in data.keys() and "users" in data.keys() and data["groupname"] in groups and len(data["users"]) > 0:
                if len(data["users"]) > 1:
                    messageS = "Users "
                    messageF = "Users "
                else:
                    messageS = "User "
                    messageF = "User "
                for user in data["users"]:
                    if user in users and user not in groups[data["groupname"]]:
                        groups[data["groupname"]]["members"].append(user)
                        group_replies[user] = []
                        messageS += user + " "
                    else:
                        messageF += user + " "
                        continue

                if len(messageF) > 6 and len(messageS) > 6:
                    mkjson["message"] = "[system]" + messageS + "added succesfully. " + "\n" + messageF + "added unsuccessfully. "
                elif len(messageF) > 6:
                    mkjson["message"] = "[system]" + messageF + "added unsuccessfully. "
                elif len(messageS) > 6:
                    mkjson["message"] = "[system]" + messageS + "added succesfully. "
                else:
                    mkjson["message"] = "[system] adding to group error. "
                mkjson["groupAdd"] = True
                send_message(client_sock, json.dumps(mkjson))
                return True
        if "!g del" in data["message"]:
            mkjson = {
                "message": "",
                "groupRemove": False,
                "group": True
            }
            messageS = ""
            messageF = ""
            if "groupname" in data.keys() and "users" in data.keys() and data["groupname"] in groups and len(
                    data["users"]) > 0:
                if len(data["users"]) > 1:
                    messageS = "Users "
                    messageF = "Users "
                else:
                    messageS = "User "
                    messageF = "User "
                for user in data["users"]:

                    if user in users and user in groups[data["groupname"]]["members"]:
                        groups[data["groupname"]]["members"].remove(user)
                        del group_replies[user]
                        messageS += user + " "
                    else:
                        messageF += user + " "
                        continue

                if len(messageF) > 6 and len(messageS) > 6:
                    mkjson[
                        "message"] = "[system]" + messageS + "removed succesfully. " + "\n" + messageF + "added unsuccessfully. "
                elif len(messageF) > 6:
                    mkjson["message"] = "[system]" + messageF + "removed unsuccessfully. "
                elif len(messageS) > 6:
                    mkjson["message"] = "[system]" + messageS + "removed succesfully. "
                else:
                    mkjson["message"] = "[system] removing from group error. "
                mkjson["groupRemove"] = True
                send_message(client_sock, json.dumps(mkjson))
                return True
            send_message(client_sock, json.dumps(
                {"error": True, "message":"Group setting error, key unknown or group doesn't exist"}))
            return True
    else:
        return False

def group_messages(client_sock, data, msg_receieved):
    try:

        if "group" in data.keys() and "group_message" in data.keys() and data["group"] and data["group_message"]:

            if "!g send" == data["message"][:7] and data["groupname"] in groups:

                data["message"] = "%s group chat: %s at %s says: %s" % (data["groupname"].capitalize(), data["username"], data["time"].split(" ")[1][:-3],
                                                                  data["message"][(len("!g send  "))+(len(data["groupname"])):])
                for member in groups[data["groupname"]]["members"]:
                    send_message(users[member], json.dumps(data))
                return True
            return True
        return False
    except:
        traceback.print_exc()


def authenticate(client_sock, data):
    if data["greeting"] and data["username"] not in users:
        users[data["username"]] = client_sock
        friendlists[data["username"]] = []
        friend_only_private[data["username"]] = False

        return True
    if data["username"] in users and data["greeting"]:
        mkjson = {
            "message": "Username already exists, restart with different username.",
            "terminate": True
        }
        send_message(client_sock, json.dumps(mkjson))
        return False
    return False

def private(client_sock, data, msg_received):
    try:
        if "destination" in data.keys() and data["destination"] and "private" in data.keys() and data["private"]:
            if data["destination"] not in users:
                mkjson = {
                    "message": "User with that username doesn't exist.",
                    "terminate": False
                }
                send_message(client_sock, json.dumps(mkjson))
                print("[system] private message failed")
                return True
            if data["destination"] in users and not friend_only_private[data["destination"]]:
                send_message(users[data["destination"]], msg_received)
                send_message(client_sock, msg_received)
                print("[system] private message succesfully sent")
                return True
            elif data["username"] in friendlists[data["destination"]] and friend_only_private[data["destination"]]:
                send_message(users[data["destination"]], msg_received)
                send_message(client_sock, msg_received)
                print("[system] private message succesfully sent")
                return True
            elif data["destination"] in users and friend_only_private[data["destination"]]:
                mkjson = {
                    "message": "User has disabled public direct messages.",
                    "private_disabled": True
                }
                send_message(client_sock, json.dumps(mkjson))
                print("[system] Direct message denied by user")
                return True
            else:
                #error
                pass
        return False
    except:
        traceback.print_exc()

def friendlist(client_sock, data):
    global friendlists
    global friend_only_private
    global users

    if "friendlist" in data.keys() and data["friendlist"]:


        reply = {
            "friendlistReply": True,
            "friendlist": True,
            "message": "",

        }
        message = ""
        if "!f show" == data["message"]:
            message = friendlists[data["username"]]
        elif "!f add" in data["message"] and data["message"].split(" ")[2] in users and data["message"].split(" ")[2] \
                not in friendlists[data["username"]]:
            friendlists[data["username"]].append(data["message"].split(" ")[2])
            message = "[system] %s added to friends list. " % (data["message"].split(" ")[2])
        elif "!f del" in data["message"] and data["message"].split(" ")[2] in users and data["message"].split(" ")[2] \
                in friendlists[data["username"]]:
            friendlists[data["username"]].remove(data["message"].split(" ")[2])
            message = "[system] %s removed from friends list. " % (data["message"].split(" ")[2])
        elif "!f enable" in data["message"]:
            friend_only_private[data["username"]] = True
            message = "[system]Only friends can send you direct messages now. "
        elif "!f disable" in data["message"]:
            friend_only_private[data["username"]] = False
            message = "[system]Everyone can send you direct messages now. "
        else:
            print("friendlist error")
        reply["message"] = message
        send_message(client_sock, json.dumps(reply))
        return True
    else:
        return False



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


# funkcija za komunikacijo z odjemalcem (tece v loceni niti za vsakega odjemalca)
def client_thread(client_sock, client_addr):
    global clients
    global users
    global friendlists
    global groups
    global group_replies

    print("[system] connected with " + client_addr[0] + ":" + str(client_addr[1]))
    print("[system] we now have " + str(len(clients)) + " clients")
    

    try:

        while True:  # neskoncna zanka
            msg_received = receive_message(client_sock)
            if not msg_received:  # ce obstaja sporocilo
                break
            try:
                data = json.loads(msg_received)

                #print(data)
                if authenticate(client_sock, data):
                    continue

                if private(client_sock, data, msg_received):
                    continue


                #ZA ONEMOGOČANJE DODATNIH FUNKCIONALOSTI ZAKOMENTIRAJTE SPODNJE VRSTICE
                if friendlist(client_sock, data):
                    continue

                if group_settings(client_sock, data):
                    continue

                if group_messages(client_sock, data, msg_received):
                    continue




                print("[" + data["username"].capitalize() + "] at [" + data["time"] + "] says: " + data["message"])
            except Exception as e:
                    #print(e)
                    pass

            for client in clients:
                send_message(client, msg_received)
    except Exception as e:
        #print(e)
        # tule bi lahko bolj elegantno reagirali, npr. na posamezne izjeme. Trenutno kar pozremo izjemo
        pass

    # prisli smo iz neskoncne zanke
    with clients_lock:
        try:
            for s in users:
                if users.get(s) == client_sock:
                    del users[s]
                    del friendlists[s]
            
        except Exception as e:
            #this throws size change erro
            #print(e)
            pass

        clients.remove(client_sock)

    print("[system] we now have " + str(len(clients)) + " clients")
    client_sock.close()

# kreiraj socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(("localhost", PORT))
server_socket.listen(1)

# cakaj na nove odjemalce
print("[system] listening ...")
clients = set()
users = {}
friendlists = {}
friend_only_private ={}
groups = {}
group_replies = {}
clients_lock = threading.Lock()
while True:
    try:
        # pocakaj na novo povezavo - blokirajoc klic
        client_sock, client_addr = server_socket.accept()
        with clients_lock:
            clients.add(client_sock)

        thread = threading.Thread(target=client_thread, args=(client_sock, client_addr));
        thread.daemon = True
        thread.start()

    except KeyboardInterrupt:
        break

print("[system] closing server socket ...")
server_socket.close()
