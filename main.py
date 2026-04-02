import os
import hashlib
from datetime import datetime
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext


LOG_FILE = "log.txt"
MAGIC = b"SFG1"
SALT_SIZE = 16


def write_log(text: str) -> None:
    now = datetime.now().strftime("%d.%m.%Y %H:%M:%S")
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"{now} - {text}\n")


def make_key(password: str, salt: bytes) -> bytes:
    return hashlib.sha256(password.encode("utf-8") + salt).digest()


def xor_bytes(data: bytes, key: bytes) -> bytes:
    result = bytearray()
    key_len = len(key)

    for i, byte in enumerate(data):
        result.append(byte ^ key[i % key_len])

    return bytes(result)


def encrypt_file_bytes(data: bytes, password: str) -> bytes:
    salt = os.urandom(SALT_SIZE)
    key = make_key(password, salt)
    check = hashlib.sha256(key).digest()
    encrypted_data = xor_bytes(data, key)
    return MAGIC + salt + check + encrypted_data


def decrypt_file_bytes(data: bytes, password: str) -> bytes:
    min_len = 4 + SALT_SIZE + 32

    if len(data) < min_len:
        raise ValueError("Файл слишком короткий или повреждён.")

    if data[:4] != MAGIC:
        raise ValueError("Это не файл формата Secure File Guard.")

    salt_start = 4
    salt_end = salt_start + SALT_SIZE
    check_end = salt_end + 32

    salt = data[salt_start:salt_end]
    saved_check = data[salt_end:check_end]
    encrypted_data = data[check_end:]

    key = make_key(password, salt)
    current_check = hashlib.sha256(key).digest()

    if saved_check != current_check:
        raise ValueError("Неверный пароль.")

    return xor_bytes(encrypted_data, key)


class SecureFileGuardApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Secure File Guard")
        self.root.geometry("760x390")
        self.root.resizable(False, False)

        self.create_widgets()

    def create_widgets(self):
        tk.Label(
            self.root,
            text="Secure File Guard",
            font=("Arial", 18, "bold")
        ).pack(pady=10)

        tk.Label(
            self.root,
            text="Приложение для шифрования и расшифровки файлов",
            font=("Arial", 11)
        ).pack()

        file_frame = tk.Frame(self.root)
        file_frame.pack(fill="x", padx=15, pady=15)

        tk.Label(file_frame, text="Выбранный файл:", font=("Arial", 11)).pack(anchor="w")

        file_row = tk.Frame(file_frame)
        file_row.pack(fill="x", pady=5)

        self.file_entry = tk.Entry(file_row, font=("Arial", 11))
        self.file_entry.pack(side="left", fill="x", expand=True, padx=(0, 8))

        tk.Button(
            file_row,
            text="Выбрать файл",
            width=16,
            command=self.select_file
        ).pack(side="right")

        password_frame = tk.Frame(self.root)
        password_frame.pack(fill="x", padx=15, pady=10)

        tk.Label(password_frame, text="Пароль:", font=("Arial", 11)).pack(anchor="w")

        self.password_entry = tk.Entry(password_frame, font=("Arial", 11), show="*")
        self.password_entry.pack(fill="x", pady=5)

        buttons_frame = tk.Frame(self.root)
        buttons_frame.pack(pady=20)

        tk.Button(
            buttons_frame,
            text="Зашифровать",
            width=16,
            height=2,
            command=self.encrypt_file
        ).grid(row=0, column=0, padx=8)

        tk.Button(
            buttons_frame,
            text="Расшифровать",
            width=16,
            height=2,
            command=self.decrypt_file
        ).grid(row=0, column=1, padx=8)

        tk.Button(
            buttons_frame,
            text="История",
            width=16,
            height=2,
            command=self.show_history
        ).grid(row=0, column=2, padx=8)

        tk.Button(
            buttons_frame,
            text="Очистить",
            width=16,
            height=2,
            command=self.clear_fields
        ).grid(row=0, column=3, padx=8)

        result_frame = tk.Frame(self.root)
        result_frame.pack(fill="x", padx=15, pady=10)

        tk.Label(result_frame, text="Статус:", font=("Arial", 11)).pack(anchor="w")

        self.result_label = tk.Label(
            result_frame,
            text="Ожидание действия пользователя",
            font=("Arial", 11),
            fg="blue",
            justify="left",
            anchor="w"
        )
        self.result_label.pack(fill="x", pady=5)

    def select_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.file_entry.delete(0, tk.END)
            self.file_entry.insert(0, file_path)
            self.result_label.config(
                text=f"Файл выбран:\n{file_path}",
                fg="blue"
            )
            write_log(f"Выбран файл: {os.path.basename(file_path)}")

    def clear_fields(self):
        self.file_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)
        self.result_label.config(
            text="Поля очищены",
            fg="blue"
        )
        write_log("Поля очищены пользователем")

    def encrypt_file(self):
        file_path = self.file_entry.get().strip()
        password = self.password_entry.get().strip()

        if not file_path:
            messagebox.showwarning("Предупреждение", "Сначала выберите файл.")
            write_log("Ошибка: попытка шифрования без выбора файла")
            return

        if not os.path.isfile(file_path):
            messagebox.showerror("Ошибка", "Файл не найден.")
            write_log(f"Ошибка: файл не найден - {file_path}")
            return

        if not password:
            messagebox.showwarning("Предупреждение", "Введите пароль.")
            write_log(f"Ошибка: попытка шифрования файла {os.path.basename(file_path)} без пароля")
            return

        try:
            with open(file_path, "rb") as f:
                original_data = f.read()

            encrypted_data = encrypt_file_bytes(original_data, password)
            output_path = file_path + ".enc"

            with open(output_path, "wb") as f:
                f.write(encrypted_data)

            self.result_label.config(
                text=f"Шифрование успешно выполнено.\nСоздан файл:\n{output_path}",
                fg="green"
            )

            write_log(
                f"Файл {os.path.basename(file_path)} успешно зашифрован в {os.path.basename(output_path)}"
            )

            messagebox.showinfo(
                "Успех",
                f"Файл успешно зашифрован.\n\nСоздан файл:\n{output_path}"
            )

        except Exception as e:
            self.result_label.config(
                text=f"Ошибка шифрования: {e}",
                fg="red"
            )
            write_log(f"Ошибка шифрования файла {os.path.basename(file_path)}: {e}")
            messagebox.showerror("Ошибка", f"Не удалось зашифровать файл.\n{e}")

    def decrypt_file(self):
        file_path = self.file_entry.get().strip()
        password = self.password_entry.get().strip()

        if not file_path:
            messagebox.showwarning("Предупреждение", "Сначала выберите файл.")
            write_log("Ошибка: попытка расшифровки без выбора файла")
            return

        if not os.path.isfile(file_path):
            messagebox.showerror("Ошибка", "Файл не найден.")
            write_log(f"Ошибка: файл не найден - {file_path}")
            return

        if not password:
            messagebox.showwarning("Предупреждение", "Введите пароль.")
            write_log(f"Ошибка: попытка расшифровки файла {os.path.basename(file_path)} без пароля")
            return

        try:
            with open(file_path, "rb") as f:
                encrypted_data = f.read()

            decrypted_data = decrypt_file_bytes(encrypted_data, password)

            if file_path.endswith(".enc"):
                base_path = file_path[:-4]
            else:
                base_path = file_path

            name, ext = os.path.splitext(base_path)
            output_path = f"{name}_decrypted{ext}"

            with open(output_path, "wb") as f:
                f.write(decrypted_data)

            self.result_label.config(
                text=f"Расшифровка успешно выполнена.\nСоздан файл:\n{output_path}",
                fg="green"
            )

            write_log(
                f"Файл {os.path.basename(file_path)} успешно расшифрован в {os.path.basename(output_path)}"
            )

            messagebox.showinfo(
                "Успех",
                f"Файл успешно расшифрован.\n\nСоздан файл:\n{output_path}"
            )

        except Exception as e:
            self.result_label.config(
                text=f"Ошибка расшифровки: {e}",
                fg="red"
            )
            write_log(f"Ошибка расшифровки файла {os.path.basename(file_path)}: {e}")
            messagebox.showerror("Ошибка", f"Не удалось расшифровать файл.\n{e}")

    def show_history(self):
        history_window = tk.Toplevel(self.root)
        history_window.title("История действий")
        history_window.geometry("760x430")

        text_area = scrolledtext.ScrolledText(
            history_window,
            wrap=tk.WORD,
            font=("Consolas", 10)
        )
        text_area.pack(fill="both", expand=True, padx=10, pady=10)

        if os.path.exists(LOG_FILE):
            with open(LOG_FILE, "r", encoding="utf-8") as f:
                text_area.insert(tk.END, f.read())
        else:
            text_area.insert(tk.END, "История пока пуста.")

        text_area.config(state="disabled")


if __name__ == "__main__":
    root = tk.Tk()
    app = SecureFileGuardApp(root)
    root.mainloop()