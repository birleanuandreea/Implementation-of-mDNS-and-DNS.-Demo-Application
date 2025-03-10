import socket
import threading
import struct
import tkinter as tk
import sqlite3
import time

# mDNS multicast address and port
MDNS_ADDR = "224.0.0.251"
MDNS_PORT = 5353


class DNS_SD_GUI:

    def __init__(self, root):

        # variabila folosita pentru stocarea TXT si A ce trebuie afisate
        self.service_data = None
        self.root = root
        self.root.title("Servicii DNS-SD disponibile")

        # Conexiune la baza de date -> SQLite database
        self.conn_db_gui = sqlite3.connect("rcpDB_try1.db")
        self.cursor_db_gui = self.conn_db_gui.cursor()  # cursor BD

        # Creare tabela de servicii in baza de date (daca nu exista)
        try:
            self.cursor_db_gui.execute(
                '''CREATE TABLE IF NOT EXISTS services(
                    ID INTEGER PRIMARY KEY AUTOINCREMENT,
                    TXT_DATA TEXT, 
                    A_DATA TEXT, 
                    SRV_DATA TEXT,
                    INSTANCE_NAME TEXT, 
                    SERVICE_NAME TEXT,
                    TTL INTEGER
                    )'''
            )
        except sqlite3.Error as e:
            print(f"SQLite error: {e}")

        # Creare frame pentru afisarea serviciilor disponibile
        self.services_frame = tk.LabelFrame(self.root, text="Servicii disponibile")  # titlul vadrului
        self.services_frame.pack(fill="both", expand=True, padx=10, pady=10)         # 'both' -> extinde cadru pe orizontala si verticala, permite extinderea in cazul redimensionarii, adauga spatiu in jurul cadrului

        # Creare Listbox pentru serviciile disponibile
        self.service_listbox = tk.Listbox(self.services_frame, height=10, width=50)
        self.service_listbox.pack(fill="both", expand=True, padx=10, pady=10) # adaugarea listei cu servicii in cadrul services_frame

        # Buton pentru a actualiza Listbox-ul (afiseaza serviciile inca disponibile in BD)
        self.refresh_button = tk.Button(self.root, text="Refresh", command=self.refresh_listbox)
        self.refresh_button.pack(pady=10)

        # Asociaza un eveniment de selectie pentru a obtine serviciul selectat cu functia on_service_selected
        self.service_listbox.bind('<<ListboxSelect>>', self.on_service_selected) # declansat cand utilizatorul selecteaza un element din lista

        # Frame pentru widget-ul de afisare a_data si txt_data cu titlu
        self.details_frame = tk.LabelFrame(self.root, text="Detalii serviciu selectat")
        self.details_frame.pack(pady=10, padx=10, fill="both", expand=True)

        # Textbox pentru afisarea IP-ului si valorilor TXT
        self.details_text = tk.Text(self.details_frame, height=10, wrap=tk.WORD)  # textul se va incadra in margini fara a desparti cuvintele
        self.details_text.pack(fill=tk.BOTH, expand=True) # 'BOTH' permite extinderea pe verticala si pe orizontala, permite redimensionarea in cazul redimensionarii ferestrei

        # Configurare socket pentru mDNS
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

        # Trimite query pentru descoperirea tuturor serviciilor disponibile in retea
        query_packet = bytes.fromhex(
            "0000 0000 0001 0000 0000 0000 "
            "09 5f 7365727669636573 07 5f 646e732d7364 04 5f 756470 05 6c6f63616c 00 "  # codificare '_services._dns-sd._udp.local' in etichete hexa, lungimi etichete si terminator de nume 00
            "00 0c 00 01 "  # tip PTR clasa IN
        )
        self.sock.sendto(query_packet, (MDNS_ADDR, MDNS_PORT))

        # Thread pentru ascultarea raspunsurilor DNS-SD
        self.receive_data_thread = threading.Thread(target=self.receive_mdns_data,
                                                    daemon=True)  # daemon -> nu interfereaza deloc cu thread-ul principal, dar se incheie odata cu acesta
        self.receive_data_thread.start()

        # Porneste timerul pentru actualizarea bazei de date
        self.timer_period = 30  # seteaza perioada de 30s
        self.timer_thread = threading.Thread(target=self.start_timer, daemon=True)
        self.timer_thread.start()

    def refresh_listbox(self):

        # Actualizeaza Listbox-ul cu numele serviciilor din baza de date
        self.service_listbox.delete(0, tk.END)  # sterge toate elementele din Listbox

        # Creeaza o conexiune separata la baza de date -> sqlLite are un mecanism de locking intern pentru diferite conexiuni la BD( management automat read/write)
        with sqlite3.connect("rcpDB_try1.db") as conn:
            cursor = conn.cursor()  # cursor BD

            # Interogare pentru a verifica dacă tabela este goala
            cursor.execute("SELECT COUNT(*) FROM services")
            row = cursor.fetchone()  # intoarce prima inregistrare dupa executarea comenzii sql

            # Verifica daca tabela este goala
            if row[0] == 0:
                print("Tabela este goala.")
                # Trimite query pentru descoperirea serviciilor disponibile in retea
                query_packet = bytes.fromhex(
                    "0000 0000 0001 0000 0000 0000 "  # id_tranzactie=0000; flags=0000 -> intrebare standard; 0001 -> o intrebare; 0000 -> 0 raspunsuri; 0000 -> 0 raspunsuri autoritare; 0000 -> 0 raspunsuri aditionale
                    "09 5f 7365727669636573 07 5f 646e732d7364 04 5f 756470 05 6c6f63616c 00 "  # codificare '_services._dns-sd._udp.local' in etichete hexa, lungimi etichete si terminator de nume 00 a.i. 9 -> _services 7 -> _dns-sd 4 -> _udp 5->local 
                    "00 0c 00 01 "  # qtype=12 -> PTR; qclass=1 -> IN
                )
                self.sock.sendto(query_packet, (MDNS_ADDR, MDNS_PORT))

            # exista servicii in BD
            # Interogheaza baza de date pentru inregistrarile care contin doar numele de servicii -> In acest punct, ne dorim sa afisam pe interfata doar posibilele servicii din reteaua locala
            cursor.execute(
                "SELECT service_name FROM services WHERE instance_name IS NULL")  # instance_name NULL -> in inregistrare apare doar numele serviciului, fara instante
            # stocheaza randurile rezultate din interogare sub forma unei liste de tuple
            rows = cursor.fetchall()

            # Adauga randurile in Listbox
            for row in rows:
                service_name = row[0]  # Service Name va fi afisat pe interfata, primul si singurul element din tuple
                self.service_listbox.insert(tk.END, service_name)
        conn.commit()

    # afiseaza IP si TXT pentru instanta care prezinta serviciul selectat de pe interfata
    def on_service_selected(self, event):

        # Obtine index-ul elementului selectat din Listbox
        selected_index = self.service_listbox.curselection()

        # Obtine numele serviciului selectat
        service_name = self.service_listbox.get(selected_index[0])

        # Verifica daca exista inregistrari complete pentru serviciul selectat in BD
        if not self.check_service_in_db(service_name):  # nu exista
            self.query_dns_sd(service_name)  # trimite intrebare DNS-SD pentru serviciul selectat
        # daca exista, se afiseaza detaliile cerute pe interfata
        else:
            self.details_text.delete("1.0", tk.END)  # curața Textbox-ul
            self.details_text.insert(tk.END,
                                     f"IP: {self.service_data[0]}\n\nTXT Values:\n{self.service_data[1]}")  # afiseaza datele pe interfata

    # Interogheaza baza de date pentru a verifica daca exista o inregistrare completa pentru serviciul selectat
    def check_service_in_db(self, service_name):

        self.cursor_db_gui.execute('''SELECT A_DATA, TXT_DATA FROM services WHERE SERVICE_NAME = ?''',
                                   (service_name,))
        print("service_name in check_servicedb", service_name)

        rows = self.cursor_db_gui.fetchall()

        for row in rows:
            # daca query-ul sqlite returneaza ceva. Daca da, se verifica validitatea/existenta inregistrarilor a si txt ce trebuie afisate
            if row is not None and row[0] is not None and row[1] is not None:
                print("Row", row)
                self.service_data = row
                return True  # exista o inregistrare completa
        return False  # nu exista o inregistrare completa

    # trimite intrebarea care cere inregistrarile PTR, A, TXT, SRV
    def query_dns_sd(self, service_name):
        # Construieste pachetul de intrebare DNS-SD
        query_packet = self.construct_query_packet_all_records(service_name)

        # Trimite intrebarea catre adresa MDNS
        self.sock.sendto(query_packet, (MDNS_ADDR, MDNS_PORT))
        print(f"Trimis interogare DNS-SD pentru serviciul {service_name}")


    """ Functie care gestioneaza raspunsurile DNS-SD"""

    def receive_mdns_data(self):
        # thread separat pentru ca functia recvfrom blocanta
        conn_receive = sqlite3.connect("rcpDB_try1.db")
        cursor_receive = conn_receive.cursor()
        while True:
            self.data, self.addr = self.sock.recvfrom(4096)
            self.newMdnsData = True
            # self.data este doar data mdns
            print(f"Received response from {self.addr}:\n{self.data.hex()}")
            # se decodifica pachetul
            self.decode_mdns_data(cursor_receive, conn_receive)
            conn_receive.commit()
            # actualizare interfata dupa primirea datelor noi pentru a nu fie nevoie apasarea butonului Refresh de fiecare data
            self.refresh_listbox()

    """ Valideaza datele din baza de date """

    def validate_data(self, txt_data, a_data, instance_name, service_name, ttl):
        if not txt_data:
            print("TXT_DATA este invalid (gol sau None).")
            return False
        if not a_data:
            print("A_DATA este invalid (gol sau None).")
            return False
        if not instance_name:
            print("INSTANCE_NAME este invalid (gol sau None).")
            return False
        if not service_name:
            print("SERVICE_NAME este invalid (gol sau None).")
            return False
        if ttl is None or ttl <= 0:  # Verificam dacă TTL este valid
            print("TTL este invalid (None sau <= 0).")
            return False

        return True  # daca toate campurile sunt valide

    """ decodarea raspunsurilor DNS-SD"""

    def decode_mdns_data(self, cursor_receive, conn_receive):
        ptr_data = ""
        srv_data = ""
        a_data = ""
        txt_data = ""
        ip_address = ""
        service_name = ""
        offset = 12  # headerul are 12 octeti

        # ! - big-endian, 6 campuri de cate 2 octeti fiecare (H-16 biti)
        header = struct.unpack("!6H", self.data[:offset])
        id, flags, qdcount, ancount, autcount, arcount = header

        total_answer_count = autcount + arcount + ancount

        if total_answer_count == 0:  # verificare intrebare
            print("Este intrebare")
            # nu ne intereseaza intrebarile
            return

        # sarim peste sectiunea cu intrebari
        for i in range(qdcount):
            # folosim flag pentru a verifica daca exista comprimare in intrebare -> Daca da, atunci nu mai avem terminatorul 00 la finalul numelui
            # comprimarea poate aparea si la inceputul numelui din intrebare
            is_compresses_question = False

            print("Q number ", i)
            print("offset intrebare ", i, " ", offset)

            # pointer la inceput de intrebare
            if (self.data[offset] & 0xC0) == 0xC0:
                offset += 2  # sarim peste pointer
                print("pointer la inceput de nume de intrebare")
                print("offset intrebare in pointer", i, " ", offset)
            else:
                # parcurgem numele necomprimat pana la intalnirea terminatorului de sir
                while self.data[offset] != 0:
                    length = self.data[offset]
                    # verificam daca apare un pointer in nume -> de obicei apare la inceput sau la final, deci dupa procesarea acestuia vom incheia parcurgerea de tip necomprimat
                    if length & 0xC0 == 0xC0:
                        print("pointer la final de nume intrebare")
                        offset += 2
                        is_compresses_question = True
                        break
                    else:
                        offset += length + 1 # skip lungime label + label
                        print("length in intrebare fara pointer ", length)

                if not is_compresses_question:  # daca avem un mesaj necomprimat, acesta are la finalul numelui un terminator de sir 00
                    offset += 1  # sarim peste terminator
                    print("offset intrebare fara pointer ", i, " ", offset)

            # sarim peste qtype si qclass, fiecare pe 2 octeti
            offset += 4


        if arcount == 0:  # Verificam numarul de records adiționale
            # am primit un raspuns general fara inregistrari aditionale
            # toate raspunsurile ar trb sa fie de tip ptr, iar in rdata va fi, de fapt, numele serviciului. De aceea nu avem nevoie de numele de la inceputul inregistrarii, ci de cel din rdata.
            print("Raspuns general fara inregistrari")
            is_compressed_without_records = False

            for _ in range(ancount):  # Iteram prin toate raspunsurile

                # sarim peste numele din raspuns
                # Verificam daca numele este comprimat (pointer)
                if (self.data[offset] & 0xC0) == 0xC0:
                    print("nume de raspuns general comprimat la inceput")
                    offset += 2
                else:
                    # Daca nu e pointer, parcurgem numele necomprimat
                    while self.data[offset] != 0:
                        length = self.data[offset]
                        if length & 0xC0 == 0xC0:  # daca descoperim un pointer la finalul numelui
                            print("nume de raspuns general comprimat la sfarsit")
                            offset += 2
                            is_compressed_without_records = True
                            break
                        offset += length + 1
                    if not is_compressed_without_records:  # daca nu are comprimare, numele se incheie cu un terminator de sir 00
                        offset += 1

                # Citim campurile de tip, clasa, TTL si lungime data
                # I - 4 octeti, H - 2 octeti
                answer_type, answer_class, ttl, rdlength = struct.unpack("!HHIH", self.data[offset:offset + 10])
                # print(f"Answer type: {answer_type}, Answer class: {answer_class}, TTL: {ttl}, RDLength: {rdlength}")
                # sarim peste campuri
                offset += 10  # sunt pe data

                if hex(answer_class) == '0x8001':  # raspuns specific cache flush
                    print("Cache flush")
                    # return

                # Extragerea datelor din raspuns (RDATA)
                rdata = self.data[offset:offset + rdlength]
                offset += rdlength  # sarim la urmatorul raspuns si procesam separat rdata pentru fiecare tip de raspuns

                # din ptr_data extragem numele de domeniu si il adugam in baza de date in coloana service_name
                if answer_type == 0xC:  # PTR Record
                    # print("Inregistrare PTR")
                    service_name = ""

                    # Procesare RDATA pentru a obtine numele serviciului
                    rdata_offset = 0
                    while rdata_offset < rdlength:  # parcurgem rdata
                        if (rdata[rdata_offset] & 0xC0) == 0xC0:  # Verificare daca avem un pointer reprezentat prin 2 octeti primii fiind '11', nume de domeniu comprimat
                            print("nume de domeniu comprimat")
                            # decodificare adresa indicata de pointer
                            pointer_address = int.from_bytes(rdata[rdata_offset:rdata_offset + 2],
                                                                 'big') & 0x3FFF  # eliminare primii 2 biti care sunt '11' cu o masca

                            # mutam indexul dupa pointer si il procesam pe acesta separat
                            rdata_offset += 2

                            # Decodificam numele de la adresa indicata de pointer
                            pointer_temp_offset = pointer_address
                            while self.data[pointer_temp_offset] != 0:  # iterare pana la terminator de sir
                                label_length = self.data[pointer_temp_offset]  # prima eticheta indica lungimea
                                if (label_length & 0xC0) == 0xC0:  # Pointer intr-un pointer, intalnit la decodificarea raspunsului _http._tcp.local
                                        pointer_temp_offset = int.from_bytes(self.data[pointer_temp_offset:pointer_temp_offset + 2], 'big') & 0x3FFF
                                else:
                                    pointer_temp_offset += 1  # skip lungime
                                    pointer_data = self.data[pointer_temp_offset:pointer_temp_offset + label_length].decode('utf-8')
                                    service_name += pointer_data  # adaugam eticheta curenta la numele serviciului
                                    pointer_temp_offset += label_length  # salt pe urmatoarea eticheta
                                    service_name += '.'  # intre etichete se pune '.' considerand standardul
                        else:  # Este un mesaj necomprimat
                            print("nu este comprimat")
                            label_length = rdata[rdata_offset]  # extragem primul octet = lungime
                            rdata_offset += 1  # sarim peste lungime
                            service_name += rdata[rdata_offset:rdata_offset + label_length].decode('utf-8')  # decodificam eticheta
                            rdata_offset += label_length  # sarim peste eticheta
                            service_name += '.'  # intre etichete se pune '.' considerand standardul

                    # Eliminare punct de la sfarsitul string-ului
                    service = service_name.rstrip('.')
                    print(f"Numele serviciului extras: {service}")

                    data = (None, None, None, None, service, ttl)
                    cursor_receive.execute(
                        '''SELECT id FROM services WHERE a_data is NULL and txt_data is NULL and service_name=?''',
                        (service,))
                    row = cursor_receive.fetchone()
                    if row is not None:
                        # exista in baza de date, nu-l mai inseram
                        cursor_receive.execute('''UPDATE services SET ttl=? where id=?''', (ttl, row[0]))
                    else:
                        # inseram serviciul nou in baza de date
                        cursor_receive.execute(
                            '''INSERT INTO services (TXT_DATA, A_DATA, SRV_DATA, INSTANCE_NAME, SERVICE_NAME, TTL) 
                                VALUES (?, ?, ?, ?, ?, ?)''',
                            data
                        )
                        print("am pus in bd")
        else:  # raspuns complet, cu inregistrari aditionale
            name = self.data[offset:offset + 2]  # primii doi octeti din eticheta
            service_name_check = False  # flag pentru a verifica daca numele de serviciu prezinta comprimare. Acesta se gaseste fie in numele din ptr, fie este reprezentat printr-un pointer in rdata ptr
            # parcurgere raspunsuri si raspunsuri aditionale
            for answ in range(total_answer_count):
                print(answ)
                # pentru a verifica daca e raspuns cu comprimare
                if (name[
                        0] & 0xC0) == 0xC0:  # se verifica primii 2 biti de 1 din eticheta( arata ca urm 14 biti reprez un pointer) printr-o masca care ii izoleaza
                    # pointer_to_service_name = name - 0xC0
                    if service_name_check == False: #ne intereseaza sa aflam service_name
                        service_name = ""
                        pointer_address_name = name
                        print("pointer_address_name raw", pointer_address_name)
                        pointer_address_name = int.from_bytes(pointer_address_name,
                                                              'big') & 0x3FFF  # determinam valoarea pointer-ului
                        print("pointer_address_name ", pointer_address_name)
                        while self.data[pointer_address_name] != 0:  # parcurgem etichetele de la adresa pointata
                            # parcurgem lungimile de etichete
                            label_length = self.data[pointer_address_name]
                            pointer_address_name += 1
                            for index in range(0, label_length):
                                service_name += chr(self.data[pointer_address_name + index])
                            pointer_address_name += label_length
                            service_name += '.'
                            print("service_name pointer: ", service_name, "pointer_address_srv", pointer_address_name)
                    offset += 2
                    print("is pointer")
                else:
                    # daca nu e pointer
                    if service_name_check == False: #ne intereseaza service_name
                        service_name = ""
                        while self.data[offset] != 0:
                            length = self.data[offset] #lungimea etichetei curente
                            offset += 1 #sarim peste lungimea etichetei
                            print("length_service_name", length)
                            for index in range(length): #construim eticheta
                                service_name += chr(self.data[offset + index])
                            service_name += '.' #separam etichetele prin '.'
                            print(service_name)
                            offset += length
                        offset += 1  # sarim peste terminator de sir
                        service_name = service_name[:-1] #se pune '.' la final din while si ne dorim sa il eliminam
                        print("service_name", service_name)
                    else: #nu ne intereseaza service_name, sarim peste
                        while self.data[offset] != 0:
                            length = self.data[offset]
                            offset += length + 1
                        offset += 1 #sarim peste terminator de sir

                print("offset: " + str(offset))

                # extragere campuri din answear section,  I - 32-bit unsigned integers (4 bytes each) pt TTL
                # print(self.data[offset:offset + 1])
                answer_type, answer_class, ttl, rdlength = struct.unpack("!HHIH", self.data[offset:offset + 10])
                if hex(answer_class) == '0x8001':
                    print("Cache flush")
                    # return
                print("Answer type:" + str(answer_type), "Answer class" + str(answer_class), "ttl: " + str(ttl),
                      "rdlength: " + str(rdlength))
                offset += 10

                rdata = self.data[offset:offset + rdlength]
                offset += rdlength #sarim la urmatorul raspuns si prelucram separat rdata pentru fiecare tip de raspuns
                index_rdata = 0
                if answer_type == 0xC:
                    # Inregistrare PTR
                    service_name_check = True #daca am ajuns la inregistrarea PTR, fie am aflat deja service_name, fie il aflam din rdata
                    nr_byte_left = rdlength
                    #cat timp mai avem rdata de parcurs si nu este pointer( verificam partea de la inceput necomprimata si separat comprimarea, daca este cazul). Specific rdata din ptr, pointer-ul se afla la final, daca acesta exista in cadrul rdata
                    while index_rdata < rdlength and not (rdata[index_rdata] & 0xC0 == 0xC0):
                        if index_rdata == rdlength - 1: # rdlength-1 este pozitia terminatorului de sir 00, caz special in care sigur am terminat de parcurs raspunsul,dar nu mai adaugam nimic la ptr_data
                            nr_byte_left = 0  # terminator de sir 00
                            index_rdata += 1
                        else:
                            effective_length_of_instance_name = rdata[index_rdata] #lungimea etichetei curente
                            index_rdata += 1 # sarim peste lungime
                            nr_byte_left = nr_byte_left - effective_length_of_instance_name - 1  # cati octeti raman pt pointeri ulteriori
                            print("nr_byte_left: " + str(nr_byte_left))
                            print("Effective length of instance name" + str(effective_length_of_instance_name))
                            for index in range(0, effective_length_of_instance_name): #construim eticheta prin decodificare utf-8
                                ptr_data += chr(rdata[index + index_rdata])
                            ptr_data += '.' #separam etichetele prin '.'
                            index_rdata += effective_length_of_instance_name #sarim peste eticheta cu indexul
                            print("Index_rdata " + str(index_rdata))
                            print("Instance name")
                            print(ptr_data)

                    while nr_byte_left > 0:
                        # este pointer
                        #print("nr_byte_left", self.data[offset - rdlength:offset - rdlength + index_rdata + 2])
                        pointer_bytes = int.from_bytes(
                            self.data[offset - rdlength + index_rdata:offset - rdlength + index_rdata + 2],
                            'big')  # extragem octetii pt pointer si convertim la int
                        print(pointer_bytes)
                        pointer_addr = pointer_bytes & 0x3FFF  # eliminam cei doi biti de 1 cu o masca
                        print("Pointer address:", pointer_addr)
                        # decodificam numele de la adresa respectiva
                        # incepem de la pointer_addr pana cand gasim null ca lungime de eticheta in sectiunea de intrebari
                        #decodificam practic service_name pentru ca in ptr_data avem hostname.service_name
                        #presupunem ca nu apare pointer in pointer
                        offset_service_name = pointer_addr
                        service_name = ""

                        while self.data[offset_service_name] != 0:
                            # parcurgem lungimile de etichete
                            label_length = self.data[offset_service_name] #lungime de eticheta
                            offset_service_name += 1 #sarim peste lungimea de eticheta
                            for index in range(0, label_length):#construim eticheta prin decodificare utf-8
                                service_name += chr(self.data[offset_service_name + index])
                            offset_service_name += label_length
                            service_name += '.' #adaugam la service_name eticheta urmata de '.'
                            print("Service name: ", service_name, " offset service name ", offset_service_name)
                        # eliminare punct de la sfarsit
                        service_name = service_name[:-1]
                        #concatenam ce am obtinut anterior cu partile din rdata comprimate
                        ptr_data += '.'
                        ptr_data += service_name
                        print("ptr_data" + ptr_data)
                        nr_byte_left -= 2 #reluam procesul pana cand nu mai sunt pointeri in rdata
                    #eliminam ultimul punct din ptr_data, daca acesta exista
                    if ptr_data[-1] == '.':
                        ptr_data = ptr_data[:-1]

                # deja suntem pe urm inregistrare
                # inregistrare A
                if answer_type == 0x01: #nu iteram, deoarece o inregistrare poate avea doar rdlength=4 pt cei 4 octeti de IP
                    a_data = struct.unpack("!BBBB", self.data[offset - rdlength:offset - rdlength + 4]) #!=big-endian, B=unsigned char
                    ip_address = ".".join(map(str, a_data))  # transforma octetii in string si concateneaza cu punct

                    print("A record")
                    print(ip_address)

                # inregistare TXT
                if answer_type == 0x10:
                    #rdata[0] este lungimea primei etichete txt. Deoarece avem doar o eticheta, nu avem nevoie explicit de lungimea ei, ci ne folosim de rdlength
                    txt_data = rdata[1:rdlength].decode('utf-8')
                    print("txt_data", txt_data)

                # inregistare SRV
                if answer_type == 0x21:
                    print("Target in srv")
                    index_rdata = 6 #sarim peste priority,weight
                    srv_data = "" #construim srv_data
                    while index_rdata < rdlength - 1: #parcurgem rdata pana la rdlength-1( srv se sfarseste cu terminator de sir, care nu ne intereseaza)
                        print("srv_data", srv_data)
                        label_length_srv = rdata[index_rdata] #lungimea etichetei curente
                        print("label_length_srv", label_length_srv)
                        index_rdata += 1 # sarim peste lg etichetei, deja am salvat-o intr-o variabila
                        if label_length_srv & 0xC0 == 0xC0:  # este pointer
                            pointer_address_srv = rdata[index_rdata - 1:index_rdata + 1] #adresa neprelucrata
                            print("pointer_address_srv raw", pointer_address_srv)
                            pointer_address_srv = int.from_bytes(pointer_address_srv, 'big') & 0x3FFF #extragem adresa prin masca eliminand primii 2 biti de 1, folositi ca flag-uri pentru a indica un pointer
                            print("pointer_address_srv ", pointer_address_srv)
                            while self.data[pointer_address_srv] != 0: #parcurgem continutul de la adresa pointata
                                # parcurgem lungimile de etichete
                                label_length = self.data[pointer_address_srv]
                                pointer_address_srv += 1 #sarim peste lg etichetei
                                for index in range(0, label_length): #decodificam eticheta utf-8
                                    srv_data += chr(self.data[pointer_address_srv + index])
                                pointer_address_srv += label_length #sarim peste eticheta
                                srv_data += '.' #concatem etichetele prin '.' conform standardului
                                print("srv_data pointer: ", srv_data, "pointer_address_srv", pointer_address_srv)
                        else: #nu este pointer, parcurgem eticheta normal
                            for index in range(label_length_srv): #decodificam eticheta utf-8
                                srv_data += chr(rdata[index + index_rdata])
                            srv_data += '.' #concatenam etichetele prin '.'
                            index_rdata += label_length_srv
                            print("index_rdata", index_rdata)
                    #scoatem ultimul punct pus in while
                    srv_data = srv_data[:-1]

                name = self.data[offset:offset + 2]
                #inceputul numelui din urmatorul raspuns

            #validam datele pentru a le integra in BD
            if self.validate_data(txt_data, a_data, ptr_data, service_name, ttl):

                data = (txt_data, ip_address, srv_data, ptr_data, service_name, ttl)

                cursor_receive.execute("SELECT srv_data, service_name, ttl FROM services")
                rows = cursor_receive.fetchall()
                found = False
                for row in rows:
                    #daca gasim aceeasi inregistrare ii modifcam doar ttl
                    if row[0] == srv_data and row[1] == service_name:
                        found = True
                        if row[2] < ttl:
                            cursor_receive.execute(
                                "UPDATE services SET TTL = ? WHERE srv_data = ? AND service_name = ?",
                                (ttl, srv_data, service_name)
                            )
                        break
                    # else:
                    #    continue

                if not found:
                    # inserare serviciu in BD
                    cursor_receive.execute(
                        '''INSERT INTO services (TXT_DATA, A_DATA, SRV_DATA, INSTANCE_NAME, SERVICE_NAME, TTL) 
                        VALUES (?, ?, ?, ?, ?, ?)''',
                        data
                    )
                # conn_receive.commit()

    """
    Functie ce codifica numele de serviciu pentru a putea fi folosit in queries
    """

    def code_name_for_query(self, name):
        encoded_name = ""
        # un serviciu este de forma _tip-serviciu._protocol.local, deci impartim numele dupa caracterul '.'
        labels = name.split('.')
        for label in labels:
            # pentru fiecare eticheta avem nevoie de lungimea etichetei intai, codificata hexa pe un octet
            length_label = len(label)
            hex_val_label = f"{length_label:02X}"  # adaugare de 0 pentru a avea 2 cifre, adica 1 octet(hexa)
            # adaugam lungimea etichetei si eticheta codificata
            encoded_name += str(hex_val_label) + self.code_label_for_query(label)
        # numele se incheie cu null
        encoded_name += "00"
        return encoded_name

    def code_label_for_query(self, label):
        encoded_label = ""
        # codificam fiecare caracter ASCII
        for c in label:
            # ord ofera codul utf-8 al caracterului sub forma de integer
            unic_c = ord(c)
            hex_val_ascii_c = f"{unic_c:02X}"  # formatam pe un octet, valoare hexa
            encoded_label += str(hex_val_ascii_c)
        return encoded_label

    """
    functie pentru a crea queries -> avem nevoie sa codificam doar numele de serviciu deoarece restul octetilor din query_all_records raman la fel.
    #Antetul se pastreaza, deoarece avem aceleasi "flag"-uri si acelasi numar de intrebari
    #Numele ramane acelasi pentru toate intrebarile din set, dar diferit fata de varianta dummy a variabilei query_all_records
    #Tipul se schimba de la intrebare la intrebare,Ptr codificare x000c=12(B10),SRV= -> x0021=33(B10), TXT -> x0010=16(B10), A -> x0001=1(B10)
    #Pentru a respecta standardul( cand ii este ceruta o inregistrare de tip PTR, un device trebuie sa trimita si SRV,TXT,A,AAA), trimitem doar PTR
    """

    def construct_query_packet_all_records(self, name):

        encoded_name = self.code_name_for_query(name)
        # print(encoded_name)
        rawquery = "0000 0000 0001 0000 0000 0000 "  # 0000 id_tranzactie; 0001-> o intrebare; 0000-> 0 raspunsuri; 0000 -> 0 raspunsuri autoritare; 0000-> 0 raspunsuri aditionale
        rawquery += encoded_name
        rawquery += "00 0c 00 01"  # inregistrare PTR de clasa IN(Internet)
        # Convertim query-ul in bytes
        return bytes.fromhex(rawquery)

    """ stergere inregistrari din baza de date al caror TTL a expirat"""

    def delete_expired_services(self):

        # conexiune noua la BD( cu aceasta vom sterge/modifica inregistrari, deci ne folosim de mecanismul de locking read/write intern al sqlLite prin intermediul unei noi conexiuni)
        conn_delete = sqlite3.connect("rcpDB_try1.db")
        cursor_delete = conn_delete.cursor()  # cursor BD

        # selectam identificatoul,numele instantei si ttl
        cursor_delete.execute('''
                      SELECT ID, TTL 
                      FROM services
                  ''')
        rows = cursor_delete.fetchall()
        for row in rows:
            ttl_row = row[1]
            # daca ttl inregistrare este mai mic decat perioada timer-ului -> inregistrarea a expirat de la ultimul apel al acestei functii
            if ttl_row - self.timer_period <= 0:
                # nu mai este valida inregistrarea, deci o stergem
                cursor_delete.execute('''DELETE FROM services WHERE ID = ?''',
                                      (row[0],))  # ne folosim de ID pentru a determina exact inregistrarea
            else:  # mai este valida, update ttl
                cursor_delete.execute('''UPDATE services SET TTL=? WHERE ID = ?''',
                                      (ttl_row - self.timer_period, row[0]))

        # Confirma modificarile si inchide conexiunea
        conn_delete.commit()
        conn_delete.close()

    def start_timer(self):
        # Apeleaza funcția de ștergere la fiecare perioada a timer-ului
        while True:
            self.delete_expired_services()
            time.sleep(self.timer_period)


def main():
    root = tk.Tk()
    dns_sd_gui = DNS_SD_GUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()