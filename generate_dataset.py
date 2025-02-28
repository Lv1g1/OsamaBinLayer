payload_dir = "payloads"
from capstone import *
import os
import random
import pefile


# DA DECIDERE SE PRENDERE SOLO PAYLOAD (UN PO' LIMITANTE), OPPURE PRENDERE TIPO LA .TEXT DA VARI ESEGUIBILI (MEGLIO MA MAGARI IN FUTURO BHO)

class Generator:
    def __init__(self, path):
        self.path = path
        self.payloads = []
        self.cs = Cs(CS_ARCH_X86, CS_MODE_64)
        self.cs.detail = True

        self.payloads_dicts = {}  # BHO io metterei tipo un dizionario con payload:list_of_instructions

        # carico i payloads
        num_files_max = 150
        for root, dirs, files in os.walk(self.path):
            if num_files_max == 0:
                break
            for file in files:
                with open(os.path.join(root, file), "rb") as f:
                    self.payloads.append(os.path.join(root, file))
                    payload_name = file.split('/')[-1]
                    self.payloads_dicts[payload_name] = {
                        'bytes': [],
                        'data_addresses': []
                    }

                    num_files_max -= 1
                    if num_files_max == 0:
                        break

    def disasm_text_section(self, file):
        pass

    def insert_random_bytes(self, payload):
        raw_bytes = []
        data_inserted_addresses = [] 
        with open(payload, "rb") as f: 
            raw_bytes = f.read()
        
        total_inserted = 0
        new_bytes = []
        for i in self.cs.disasm(raw_bytes, 0x0):
            new_bytes.append(i.bytes)
            prob = random.randint(0, 100)

            if i.mnemonic == '.byte':
                data_inserted_addresses.append(i.address)
                continue

            if prob < 5:
                # inserisco 1 byte random
                random_num = random.randint(1, 8)
                for x in range(random_num):
                    new_bytes.append(bytes([random.randint(0, 255)]))
                    data_inserted_addresses.append(i.address + i.size + x + total_inserted)
                    total_inserted += 1          
        payload_name = payload.split('/')[-1]

        new_bytes_v2 = []
        for l in new_bytes:
            new_bytes_v2.append(list(l))

        self.payloads_dicts[payload_name]['bytes'] = new_bytes_v2
        self.payloads_dicts[payload_name]['data_addresses'] = data_inserted_addresses            
        
    def print_disasm(self, payload_name):
        raw_bytes_arr = self.payloads_dicts[payload_name]['bytes']
    
        raw_bytes = []

        

        for arr in raw_bytes_arr:
            for byte in arr:
                raw_bytes.append(byte)
        raw_bytes = bytearray(raw_bytes)
        with open(f"InstrDisasm{payload_name}.txt", "w+") as f:
            for i in self.cs.disasm(raw_bytes, 0x0):
                f.write(f"{i.address}: {i.mnemonic} {i.op_str}\n")

        



if __name__ == "__main__":
    g = Generator(payload_dir)
    print(g.payloads)


    for p in g.payloads:
        try:
            g.insert_random_bytes(p)
            payload_name = p.split('/')[-1]

            g.print_disasm(payload_name)
        except Exception as e:
            print(f"Errore: {e}")
            continue
    print(g.payloads_dicts)
    # save dict to file
    import json
    with open("payloads_dict.json", "w+") as f:
        json.dump(g.payloads_dicts, f)
