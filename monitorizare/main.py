import struct
import threading
import tkinter as tk
import socket
import psutil

MDNS_ADDR = '224.0.0.251'
MDNS_PORT = 5353


class MonitorGUI:
    def __init__(self, root):
        self.newMdnsData = None
        self.addr = None
        self.query = None
        self.target_name = '_services._dns-sd._udp.local'   # primul query primit
        self.target_name2 = '_resources._tcp.local'         # al doilea query primit
        self.root = root
        self.root.title("Monitorizare resurse")
        # configurate la nivel de interfata
        self.hostname = None
        self.ttl = None
        self.selected_values = None
        self.answer_packet = None
        self.submit_status = False  # pentru butonul de Submit

        # Control String pentru hostname
        # etichete pentru Hostname
        tk.Label(root, text="Hostname:").grid(row=0, column=0, padx=10, pady=5,
                                              sticky="w")  # padx-> extindere sus/jos; pady -> extindere stanga/dreapta ; sticky 'w' -> aliniere la stanga (vest)
        self.hostname_entry = tk.Entry(root, width=30)  # tk.Entry -> tk widget pentru a permite introducerea unei linii de text
        self.hostname_entry.grid(row=0, column=1, padx=10, pady=5)  # plasare imediat la dreapta etichetei

        # Control Numeric pentru TTL
        # etichete pentru TTL
        tk.Label(root, text="TTL:").grid(row=1, column=0, padx=10, pady=5, sticky="w")
        self.ttl_spinbox = tk.Spinbox(root, from_=1, to=3600,
                                      width=10)  # tk.Spinbox -> tk widget pentru a selecta din mai multe variante sau permite introducerea manuala a unei valori
        self.ttl_spinbox.grid(row=1, column=1, padx=10, pady=5, sticky="w")

        # Listbox pentru selectii multiple pentru diferite resurse
        tk.Label(root, text="Select Values:").grid(row=2, column=0, padx=10, pady=5, sticky="w")
        # permite selecatia multipla
        self.listbox = tk.Listbox(root, selectmode="multiple", height=4)
        options = ["Memorie utilizata", "Incarcare procesor", "Numar procese active", "Procent baterie", "Numar procesoare"]
        # introducerea optiunilor in lista
        for option in options:
            self.listbox.insert(tk.END, option)
        self.listbox.grid(row=2, column=1, padx=10, pady=5, sticky="w")

        # Buton de Submit
        submit_button = tk.Button(root, text="Submit", command=self.submit)
        submit_button.grid(row=3, column=0, columnspan=2, pady=10)

        # Query Status Label folosit pentru primirea intrebarii generale (care nu cere inregistrari aditionale)
        tk.Label(root, text="Query Status:").grid(row=4, column=0, padx=10, pady=5, sticky="w")
        self.query_status_label = tk.Label(root, text="Waiting...", fg="blue")
        self.query_status_label.grid(row=4, column=1, padx=10, pady=5, sticky="w")

        # Query Status with Records Label folosit pentru primirea intrebarii care cere inregistrari aditionale
        tk.Label(root, text="Query Status with Records:").grid(row=5, column=0, padx=10, pady=5, sticky="w")
        self.query_status_with_records_label = tk.Label(root, text="No records yet", fg="orange")
        self.query_status_with_records_label.grid(row=5, column=1, padx=10, pady=5, sticky="w")

        # Reset Button pt status (reseteaza ambele statusuri)
        reset_button = tk.Button(root, text="Reset Status", command=self.reset_status)
        reset_button.grid(row=6, column=0, columnspan=2, pady=10)

        # socket
        self.sock = socket.socket(socket.AF_INET,
                                  socket.SOCK_DGRAM)  # socket IPv4, UDP; mDNS functioneaza pe baza de UDP
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,
                             1)  # SO_REUSEADDR -> ne ajuta sa asociem un socket cu un port/o adresa deja folosite
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL,
                             1)  # initial 1 pentru a restrictiona pachetul la reteaua locala
        # Idee de baza: la fiecare "router hop", ttl scade cu 1. La ttl=0, se renunta la pachet
        mreq = struct.pack("4sl", socket.inet_aton(MDNS_ADDR),
                           socket.INADDR_ANY)  # 4sl -> sir de 4 caractere, urmat de long int
        # socket.inet_aton(MDNS_ADDR) -> converteste '224.0.0.251' in sir de 4 octeti
        # socket.INADDR_ANY -> echivalent 0 scris ca long int -> asculta trafic de tip multicast de pe toate interfetele
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                             mreq)  # adaugam socket la grupul de multicast definit mai sus. Operatiunea este necesara, deoarece traficul unicast este "privit" diferit fata de cel multicast. Practic mesajele multicast sunt mai degraba trimise grupului de multicast decat mai multor gazde separat
        try:
            self.sock.bind(('0.0.0.0', MDNS_PORT))
            print(f"Successfully bound to {MDNS_ADDR}:{MDNS_PORT}")
        except OSError as e:
            print(f"Error binding socket: {e}")

        self.receive_question_thread = threading.Thread(target=self.receive_question,
                                                        daemon=True)  # daemon -> nu interfereaza deloc cu thread-ul principal, dar se incheie odata cu acesta
        self.receive_question_thread.start()

    # apasarea butonului confirma ca au fost configurate hostname-ul, TTL si resursele
    def submit(self):
        self.hostname = self.hostname_entry.get()
        self.ttl = self.ttl_spinbox.get()
        selected_indices = self.listbox.curselection()  # Obtine indicii valorilor selectate
        self.selected_values = [self.listbox.get(i) for i in selected_indices]  # Obtine valorile
        print(f"Hostname: {self.hostname}, TTL: {self.ttl}, Selected Values: {self.selected_values}")
        self.submit_status = True
        print("Submit",self.submit_status)

    # resetam statusurile de pe interfata
    def reset_status(self):
        self.query_status_with_records_label.config(text="No records yet", fg="orange")
        self.query_status_label.config(text="Waiting...", fg="blue")

    # socket-ul asculta raspunsurile primite
    def receive_question(self):
        while True:
            self.query, self.addr = self.sock.recvfrom(4096)  # self.query este practic doar raspunsul mdns
            self.newMdnsData = True
            print(f"Received response from {self.addr}:\n{self.query.hex()}")
            self.decode_mdns_question()

    # decodificarea intrebarilor primite pentru a gasi intrebarea care cere serviciile disponibile sau cea care cere raspunsurile aditionale pentru serviciul creat
    def decode_mdns_question(self):

        offset = 12  # headerul are 12 octeti

        # ! - big-endian, 6 campuri de cate 2 octeti fiecare (H-16 biti)
        header = struct.unpack("!6H", self.query[:offset])  # 6H-> 6 unsigned short -> 6 val pe cate 2 octeti fara semn
        id, flags, qdcount, ancount, autcount, arcount = header
        total_answer_count = ancount + autcount + arcount

        if total_answer_count == 0:
            print("Este intrebare")

            # e intrebare, deci o decodificam
            for _ in range(qdcount):
                # folosit pentru a sari peste terminatorul de sir, neintalnit la comprimare
                is_compressed=False
                name_parts = []  # pentru a stoca labels din numele intreg al intrebarii

                # verificare intrebare cu comprimare
                if self.query[offset] & 0xC0 == 0xC0:  # numele de intrebare incepe cu pointer
                    is_compressed=True
                    # extragerea adresei care e pe 2 octeti
                    pointer_address_query = self.query[offset:offset+2]
                    offset+=2
                    print("pointer_address_query raw", pointer_address_query)
                    # eliminarea celor 2 biti de '11', ramanand doar offsetul spre care indica pointerul
                    pointer_address_query = int.from_bytes(pointer_address_query, 'big') & 0x3FFF
                    print("pointer_address_query ", pointer_address_query)
                    # decodificare etichete indicate de pointer pana la intalnirea terminatorului de sir
                    while self.query[pointer_address_query] != 0:
                        # parcurgem lungimile de etichete
                        aux=""
                        # prima eticheta indica lungimea label-ului ce urmeaza
                        label_length = self.query[pointer_address_query]
                        pointer_address_query += 1 # skip length
                        for index in range(0, label_length):
                            aux += chr(self.query[pointer_address_query + index])
                        pointer_address_query += label_length # skip label
                        print("query_data pointer: ", aux, "pointer_address_query", pointer_address_query)
                        name_parts.append(aux)  # adaugarea datelor indicate de pointer
                else:
                    #numele din intrebare nu incepe cu pointer, deci fie este necomprimat, fie are o parte comprimata la final
                    while self.query[offset] != 0:  # numele de domeniu se termina cu "00"
                        length = self.query[offset]  # primul octet reprezinta lungimea label-ului ( care include si '_' )
                        if length & 0xC0 == 0xC0 : # este pointer
                            is_compressed=True
                            pointer_address_query = self.query[offset:offset + 2] # pointerule pe 2 octeti
                            offset += 2
                            print("pointer_address_query raw", pointer_address_query)
                            pointer_address_query = int.from_bytes(pointer_address_query, 'big') & 0x3FFF
                            print("pointer_address_query ", pointer_address_query)
                            while self.query[pointer_address_query] != 0:
                                # parcurgem lungimile de etichete indicate de pointer
                                label_length = self.query[pointer_address_query]
                                pointer_address_query += 1
                                aux=""
                                for index in range(0, label_length):
                                    aux += chr(self.query[pointer_address_query + index])
                                pointer_address_query += label_length
                                print("query_data pointer: ", aux, "pointer_address_query", pointer_address_query)
                                name_parts.append(aux)
                            break # avand pointer la final , nu mai are si terminator de sir
                        offset += 1  # skip lungime de label
                        label = self.query[offset:offset + length].decode('utf-8')  # decodare parti din nume
                        name_parts.append(label)
                        offset += length  # mutare la urmatorul label

                    if not is_compressed:
                        offset += 1  # skip terminator
                    # numele din intrebare
                    query_name = ".".join(name_parts)  # unificam numele de domeniu prin '.'
                    print("Decode name: ", query_name)

                # skip qtype si qclass din intrebare
                offset += 4

                if self.submit_status:  # trimitem informatii despre serviciul nostru doar daca le-am setat
                    # am primit intrebare generala -> deci trimitem doar ptr cu numele serviciului nostru
                    if self.target_name == query_name:  # verificam daca am primit intrebarea care cere serviciile disponibile
                        # setam status gui
                        self.query_status_label.config(text="Query Received", fg="green")
                        # trimit raspuns doar cu PTR
                        self.send_dns_sd_response(query_name)

                    # am primit intrebare detaliata despre serviciul nostru
                    if self.target_name2 == query_name:
                        # setam status gui
                        self.query_status_with_records_label.config(text="Records Found", fg="red")
                        # trimit raspuns complet cu PTR, SRV, TXT, A
                        self.send_dns_sd_response(query_name)

    # codificarea pachetelor de raspuns
    def send_dns_sd_response(self, query_name):

        ttl = format(int(self.ttl),
                     '08x')  # ttl preluat din interfata este formatat conform standardului, pe 4 octeti (echivalent 8 cifre hexa)
        _resources_tcplocal = "0A 5F 7265736F7572636573 04 5F 746370 05 6C6F63616C 00"  # numele serviciului oferit codificat in hexa insotit de etichetele de lungime -> 10 _resources 4 _tcp 5 local 0 ,0 fiind terminator de nume conform standard
        _resources_tcplocal.replace(" ", "")  # eliminam spatiile

        # hostname-ul de pe interfata
        hostname_hex = self.hostname.encode('utf-8').hex()  # utf-8 standard pentru eticheta dns-sd
        hostname_length = format(len(self.hostname), '02x')  # lungime hostname pe un octet (2 cifre hexa)

        # debug
        print("_resources_tcplocal: ", _resources_tcplocal)
        print("hostname_hex: ", hostname_hex)
        print("hostname_length: ", hostname_length)

        # verificam numele din intrebare. Daca este '_services._dns-sd._udp.local' inseamna ca ni se cere doar numele serviciului nostru (PTR), fara alte detalii
        if query_name == self.target_name:
            # codificarea PTR cu name, type, class, ttl, data length, domain name
            data_length_ptr = format(len('_resources_tcplocal') + 3 + 1, '04x') #data_length este pe 2 octeti -> fara puncte , nu e necesar, se ia doar dupa lungimile de eticheta. Se adauga 4 pt ca avem 3 lungimi de eticheta si 00 terminator

            # codificarea _services_dns-sd_udp_local insotita cu etichete care indica dimeniunea label-urilor plus terminator de sir '00'
            ptr = ("09 5f 73 65 72 76 69 63 65 73 07 5f 64 6e 73 2d 73 64 04 5f 75 64 70 05 6c 6f 63 61 6c 00"  # name
                   + "00 0c" + "0001" + ttl  # type, class IN, ttl
                   + data_length_ptr + _resources_tcplocal)  # data length, domain name

            self.answer_packet = bytes.fromhex(
                "0000 8400 0000 0001 0000 0000"  # DNS Header
                + ptr.replace(" ", "")
            )

            # trimit raspuns general, adica fara inregistrari aditionale
            self.sock.sendto(self.answer_packet, (MDNS_ADDR, MDNS_PORT))

            print("am trimis raspuns general")

        # daca numele din intrebare este '_resources._tcp.local', atunci ni se cer detalii in legatura cu serviciul nostru
        elif query_name == self.target_name2:

            # codificare PTR cu name, type, class, ttl, data length, domain name format din hostname si numele serviciului
            data_length_ptr = format(len('_resources_tcplocal') + len(self.hostname) + 3 + 1 + 1, '04x') # adaugam 5 deoarece avem 4 lungimi de etichete( 3 de la resources_tcp_local[ vezi mai sus pe larg] si lungimea numelui de gazda) si un terminator de nume, toate in formatul de 2 octeti
            print("data_length_ptr: ", data_length_ptr)
            ptr = (_resources_tcplocal # campul name din ptr
                   + "000C 0001 " # tipul si clasa inregistrarii
                   + ttl
                   + data_length_ptr # lungime camp rdata
                   + hostname_length + hostname_hex + _resources_tcplocal) # rdata cu lungimea numelui de gazda, numele de gazda in hexa si numele de serviciu, cu tot cu lungimile sale de etichete si terminatorul de sir
            # print("ptr ", ptr)


            # codificare SRV cu instance, service, protocol, name, type, class, ttl, data length, priority, weight, port, target
            data_length_srv = format(len(self.hostname) + 2 + 2 + 2 + 1 + 7, '04x') # lungime hostname, 2 octeti priority, 2 octeti weight, 2 octeti port, un octet pt lg hostname, 7 octeti pt local( 1 lungime "local", 5 "local", 1 terminator de nume)
            port = format(5353, '04x')  # port pe 2 octeti
            srv = (hostname_length + hostname_hex + _resources_tcplocal # nume de gazda + nume serviciu
                   + "0021 0001" # tip, clasa
                   + ttl
                   + data_length_srv + format(0, '08x')  # priority si weight sunt 0, fiecare pe 2 octeti
                   + port + hostname_length + hostname_hex + "056C6F63616C00")  # port + nume gazda + 'local' codificat cu terminator '00'


            # codificare TXT cu name, type, class, ttl, data length pe 2 octeti, (txt length, txt data) pentru fiecare cuvant
            # dictionar care asociaza optiuni de resurse de pe interfata cu functiile care obtin resursele respective
            options_methods = {
                "Memorie utilizata": self.get_memory_usage,
                "Incarcare procesor": self.get_cpu_load,
                "Numar procese active": self.get_active_processes,
                "Procent baterie": self.get_battery,
                "Numar procesoare": self.get_cpu_count,
            }
            txt_data = []
            for value in self.selected_values: # iteram prin optiunile selectate de utilizator
                #apelam practic functia asociata optiunii din gui care determina resursa respectiva si o adaugam in campul rdata al inregistrarii txt aferente
                result = options_methods[value]()
                txt_data += result
            txt_data_str = ''.join(txt_data)  # transforma lista intr-un singur sir
            txt_data_hex = txt_data_str.encode('utf-8').hex() # codificare utf-8, conform standardului
            data_length_txt = format(len(txt_data_str) + 1,
                                     '04x')  # pe 2 octeti, lungimea totala a TXT_DATA, + 1 pentru fiecare label de lungime (in cazul nostru doar unul)
            length_txt = format(len(txt_data_str),
                                '02x')  # pe 1 octet, lungime pentru fiecare label din TXT_DATA (in cazul nostru doar unul)
            txt = (hostname_length + hostname_hex + _resources_tcplocal     # name
                   + "0010 0001" + ttl  # type, class, ttl
                   + data_length_txt + length_txt + txt_data_hex)   # data_length, txt_length, txt


            # codificare A cu name, type, class, ttl, data length pe 2 octeti = 0004, address
            a_data_length = "0004" # ip pe 4 octeti
            hostname = socket.gethostname()
            address = socket.gethostbyname(hostname)  # Adresa IP locala pe baza hostname-ului instantei pe care se ruleaza programul
            print("address: " + address)
            # conversie adresa IP in hexa
            ip_parts = address.split(".")   # eliminarea punctelor
            ip_hex = "".join(f"{int(part):02x}" for part in ip_parts) # fiecare parte formata ca un intreg pe 2 cifre hexa(un octet) de ex 192 -> c0
            print("ip_hex: " + ip_hex)

            a = (hostname_length + hostname_hex + "05 6C6F63616C  00"  # hostname si domeniu = 'local' codificat cu terminator '00'
                 + "0001 0001"  # tip si clasa
                 + ttl + a_data_length + ip_hex)  # ttl, lungime, adresa
            # print("A: " + a)

            self.answer_packet = bytes.fromhex(
                "0000 8400 0000 0001 0000 0003"  # DNS Header  0000->id tranzactie; 8400-> raspuns standard dns, fara eroare, 0000-> 0 intrebari; 0001-> un raspuns; 0000->0 raspunsuri autoritare; 0003-> 3 raspunsuri aditionale( ni s-a cerut ptr si, conform standard, trimitem si srv,txt,a
                + ptr.replace(" ", "")
                + srv.replace(" ", "")
                + txt.replace(" ", "")
                + a.replace(" ", "")
            )

            # trimitere pachet complet cu PTR, SRV, TXT, A
            self.sock.sendto(self.answer_packet, (MDNS_ADDR, MDNS_PORT))

            print("am trimis raspuns cu inregistrari")

    # functii pentru obtinerea resurselor cu ajutorul bibliotecii psutil
    # aflarea memoriei RAM utilizata si convertirea in GB
    def get_memory_usage(self):
        memory = psutil.virtual_memory()
        print(f"Memorie utilizata RAM: {memory.used / (1024 ** 3):.2f} GB")
        return f"Memorie utilizata RAM: {memory.used / (1024 ** 3):.2f} GB "  # conversie in GB din bytes cu 2 zecimale

    # numarul total de procese active
    def get_active_processes(self):
        # o lista cu ID-urile tuturor proceselor active
        process_count = len(psutil.pids())
        print(f"Numar procese active: {process_count}")
        return f"Numar procese active: {process_count} "

    # procentul de utilizare al procesorului, calculat pe baza unei pauze de 1 secunda
    def get_cpu_load(self):
        cpu_load = psutil.cpu_percent(interval=1)
        print(f"Incarcare procesor: {cpu_load}%")
        return f"Incarcare procesor: {cpu_load}% "

    # procentul bateriei disponibile
    def get_battery(self):
        print("Procent baterie: ",psutil.sensors_battery().percent)
        return f"Procent baterie: {psutil.sensors_battery().percent}%"

    # numarul total de procesoare fizice
    def get_cpu_count(self):
        cpu_count = psutil.cpu_count(logical=False) # logical = False exclude nucleele logice
        print(f"Numar procesoare: {cpu_count}")
        return f"Numar procesoare: {cpu_count} "


if __name__ == "__main__":
    root = tk.Tk()
    app = MonitorGUI(root)
    root.mainloop()