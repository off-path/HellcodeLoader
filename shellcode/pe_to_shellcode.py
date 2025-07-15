import pefile
import sys

def generate_shellcode(input_file):
    try:
        pe = pefile.PE(input_file)
        text_data = bytearray()
        func_data = bytearray()
        
        for section in pe.sections:
            name = section.Name.decode().strip('\x00')
            if name == '.00start':
                text_data = section.get_data()
            elif name == '.func':
                func_data = section.get_data()
   
        combined =func_data + text_data     
    

        output = "unsigned char shellcode[] = {\n    "
        
        for i, byte in enumerate(combined):
            output += f"0x{byte:02x}"
            if i != len(combined) - 1:
                output += ", "
                if (i + 1) % 12 == 0:
                    output += "\n    "
        
        output += "\n};\n"
        output += f"unsigned int shellcode_len = {len(combined)};"
        
        return output
        
    except Exception as e:
        print(f"Erreur: {str(e)}")
        return None
    finally:
        pe.close()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python pe_to_shellcode.py <fichier.exe>")
        sys.exit(1)
    
    result = generate_shellcode(sys.argv[1])
    if result:
        print(result)
        with open("shellcode.h", "w") as f:
            f.write(result)
        print("\nFichier shellcode.h généré avec succès!")