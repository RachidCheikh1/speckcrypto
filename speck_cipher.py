import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
from PIL import Image, ImageTk  # Import Pillow for handling JPEG images
import random

# Conversion des caractères en paires de valeurs 16 bits
def text_to_pairs(text):
    pairs = []
    for i in range(0, len(text), 2):
        if i + 1 < len(text):
            pair = (ord(text[i]), ord(text[i + 1]))
        else:
            pair = (ord(text[i]), 0)
        pairs.append(pair)
    return pairs

# Conversion des paires de valeurs 16 bits en texte
def pairs_to_text(pairs):
    text = ""
    for x, y in pairs:
        text += chr(x) + chr(y)
    return text

# Génération de clés aléatoires
def generate_key(key_size):
    return [random.randint(0, 65535) for _ in range(key_size)]

# Implémentation simplifiée de l'algorithme Speck pour des fins de démonstration
def speck_encrypt(x, y, key):
    mask = (2 ** 16) - 1
    for k in key:
        x = (x >> 7 | x << (16 - 7)) & mask
        x = (x + y) & mask
        x ^= k
        y = (y << 2 | y >> (16 - 2)) & mask
        y ^= x
    return x, y

def speck_decrypt(x, y, key):
    mask = (2 ** 16) - 1
    for k in reversed(key):
        y ^= x
        y = (y >> 2 | y << (16 - 2)) & mask
        x ^= k
        x = (x - y) & mask
        x = (x << 7 | x >> (16 - 7)) & mask
    return x, y

# Fonction de cryptage appelée par l'interface utilisateur
def encrypt():
    plaintext = text_plaintext.get("1.0", tk.END).strip()
    key_size = int(key_size_var.get())
    key = generate_key(key_size)
    pairs = text_to_pairs(plaintext)
    encrypted_pairs = [speck_encrypt(x, y, key) for x, y in pairs]
    ciphertext = pairs_to_text(encrypted_pairs)
    text_ciphertext.delete("1.0", tk.END)
    text_ciphertext.insert(tk.END, ciphertext)
    entry_key.delete(0, tk.END)
    entry_key.insert(0, ' '.join(map(str, key)))
    label_key_size.config(text=f"Taille de la clé: {key_size * 16} bits")

# Fonction de décryptage appelée par l'interface utilisateur
def decrypt():
    try:
        ciphertext = text_ciphertext.get("1.0", tk.END).strip()
        key = [int(k) for k in entry_key.get().split()]
        pairs = text_to_pairs(ciphertext)
        decrypted_pairs = [speck_decrypt(x, y, key) for x, y in pairs]
        plaintext = pairs_to_text(decrypted_pairs).rstrip('\x00')  # Supprimer les caractères nuls
        text_plaintext.delete("1.0", tk.END)
        text_plaintext.insert(tk.END, plaintext)
    except ValueError:
        messagebox.showerror("Erreur", "Entrée invalide. Veuillez entrer une clé valide.")

# Fonction pour copier le texte chiffré dans le presse-papiers
def copy_ciphertext():
    root.clipboard_clear()
    root.clipboard_append(text_ciphertext.get("1.0", tk.END).strip())
    root.update()  # Maintenant le contenu du presse-papiers est disponible

# Fonction pour copier la clé dans le presse-papiers
def copy_key():
    root.clipboard_clear()
    root.clipboard_append(entry_key.get())
    root.update()  # Maintenant le contenu du presse-papiers est disponible

# Création de l'interface graphique
root = tk.Tk()
root.title("Démonstration de l'algorithme Speck")

# Charger l'image avec Pillow
img = Image.open("C:/Users/ABDELLAHI/Downloads/ensa.jpg")
img = img.resize((300, 200))  # Redimensionner l'image pour une taille plus petite
image = ImageTk.PhotoImage(img)

# Cadre principal
mainframe = tk.Frame(root, background="#f8f9fa")
mainframe.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=10, pady=10)

# Afficher l'image en haut de l'interface
label_image = tk.Label(mainframe, image=image)
label_image.grid(row=0, column=1, columnspan=2, sticky=(tk.W, tk.E), padx=5, pady=5)

# Ajouter les titres au-dessus de l'image
label_title_1 = tk.Label(mainframe, text="Ecole Nationale des Sciences Appliquées", font=("Helvetica", 12, "bold"), background="#f8f9fa")
label_title_1.grid(row=1, column=1, columnspan=2, padx=5, pady=2)

label_title_2 = tk.Label(mainframe, text="Projet Cryptage avec SPECK", font=("Helvetica", 10), background="#f8f9fa")
label_title_2.grid(row=2, column=1, columnspan=2, padx=5, pady=2)

# Cadre pour le texte en clair
frame_plaintext = tk.LabelFrame(mainframe, text="Texte en clair", background="#f8f9fa")
frame_plaintext.grid(row=3, column=1, columnspan=2, sticky=(tk.W, tk.E), padx=5, pady=2)
text_plaintext = tk.Text(frame_plaintext, height=4, width=40, background="#ffffff", borderwidth=2, relief="solid")
text_plaintext.grid(row=1, column=1, padx=5, pady=2)

# Cadre pour la clé
frame_key = tk.LabelFrame(mainframe, text="Clé", background="#f8f9fa")
frame_key.grid(row=4, column=1, columnspan=2, sticky=(tk.W, tk.E), padx=5, pady=2)
entry_key = tk.Entry(frame_key, width=40, background="#ffffff", borderwidth=2, relief="solid")
entry_key.grid(row=1, column=1, padx=5, pady=2)

# Cadre pour la taille de la clé
frame_key_size = tk.LabelFrame(mainframe, text="Taille de la clé", background="#f8f9fa")
frame_key_size.grid(row=5, column=1, columnspan=2, sticky=(tk.W, tk.E), padx=5, pady=2)
key_size_var = tk.StringVar(value='4')
key_size_entry = tk.Entry(frame_key_size, width=40, textvariable=key_size_var, background="#ffffff", borderwidth=2, relief="solid")
key_size_entry.grid(row=1, column=1, padx=5, pady=2)

# Cadre pour le texte chiffré
frame_ciphertext = tk.LabelFrame(mainframe, text="Texte chiffré", background="#f8f9fa")
frame_ciphertext.grid(row=6, column=1, columnspan=2, sticky=(tk.W, tk.E), padx=5, pady=2)
text_ciphertext = tk.Text(frame_ciphertext, height=4, width=40, background="#ffffff", borderwidth=2, relief="solid")
text_ciphertext.grid(row=1, column=1, padx=5, pady=2)

# Cadre pour les boutons
frame_buttons = tk.Frame(mainframe, background="#f8f9fa")
frame_buttons.grid(row=7, column=1, columnspan=2, sticky=(tk.W, tk.E), padx=5, pady=2)
tk.Button(frame_buttons, text="Crypter", command=encrypt, background="#007bff", foreground="white").grid(row=1, column=1, padx=2, pady=2, sticky=(tk.W, tk.E))
tk.Button(frame_buttons, text="Décrypter", command=decrypt, background="#007bff", foreground="white").grid(row=1, column=2, padx=2, pady=2, sticky=(tk.W, tk.E))
tk.Button(frame_buttons, text="Copier la clé", command=copy_key, background="#007bff", foreground="white").grid(row=1, column=3, padx=2, pady=2, sticky=(tk.W, tk.E))
tk.Button(frame_buttons, text="Copier le texte chiffré", command=copy_ciphertext, background="#007bff", foreground="white").grid(row=1, column=4, padx=2, pady=2, sticky=(tk.W, tk.E))

# Résultats
label_key_size = tk.Label(mainframe, text="", anchor="w", background="#f8f9fa")
label_key_size.grid(row=8, column=1, columnspan=2, sticky=(tk.W, tk.E), padx=5, pady=2)

root.mainloop()
