import os

def save_configuration(config_content, config_path):
    try:
        # make sure folder configs ada
        os.makedirs(os.path.dirname(config_path), exist_ok=True)

        # Menyimpan file konfigurasi ke path yang diberikan
        with open(config_path, "w", encoding="utf-8") as config_file:
            config_file.write(config_content)
    except Exception as e:
        print(f"[!] Gagal menyimpan konfigurasi: {e}")