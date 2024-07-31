import os
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
from elftools.elf.elffile import ELFFile
from intelhex import IntelHex


def read_elf_file(input_file):
    try:
        with open(input_file, 'rb') as f:
            elf = ELFFile(f)
            binary_data = bytearray()
            for segment in elf.iter_segments():
                if segment['p_type'] == 'PT_LOAD':
                    binary_data.extend(segment.data())
            return binary_data
    except Exception as e:
        messagebox.showerror("Error", f"ELF File Read Error: {str(e)}")
        return None


def read_hex_file(input_file):
    try:
        ih = IntelHex(input_file)
        binary_data = ih.tobinarray()
        return binary_data
    except Exception as e:
        messagebox.showerror("Error", f"HEX File Read Error: {str(e)}")
        return None


def pad_firmware(input_file, output_file, desired_size, bytes_per_line):
    # 파일 확장자에 따라 파일 처리
    if input_file.endswith('.elf'):
        data = read_elf_file(input_file)
        if data is None:
            return
    elif input_file.endswith('.hex'):
        data = read_hex_file(input_file)
        if data is None:
            return
    else:
        try:
            with open(input_file, 'rb') as f:
                data = f.read()
        except FileNotFoundError:
            messagebox.showerror("Error", "Input file not found, please check the path.")
            return
        except PermissionError:
            messagebox.showerror("Error", "You do not have access to the input file. Please check the permissions of the file.")
            return

    # 현재 파일 크기 확인
    current_size = len(data)

    if desired_size is not None:
        # 파일이 이미 원하는 크기보다 크거나 같은 경우 에러 경고
        if current_size > desired_size:
            messagebox.showerror("Error", "The input file is larger than the set size.")
            return

        # 파일이 이미 원하는 크기와 같다면 패딩 불필요
        if current_size == desired_size:
            messagebox.showinfo("Notice", "The file is already the same size as you want, no padding is performed.")
            padded_data = data
        else:
            # 파일이 원하는 크기보다 작다면 0xFF로 패딩
            padding_size = desired_size - current_size
            padded_data = data + b'\xFF' * padding_size
    else:
        padded_data = data

    # 출력 파일 디렉토리 확인 및 생성
    output_dir = os.path.dirname(output_file)
    if output_dir and not os.path.exists(output_dir):
        try:
            os.makedirs(output_dir)
        except PermissionError:
            messagebox.showerror("Error", f"Unable to create directory: {output_dir}. Check your authority.")
            return

    # 새로운 파일에 패딩된 데이터 쓰기
    try:
        with open(output_file, 'wb') as f:
            f.write(padded_data)
    except PermissionError:
        messagebox.showerror("Error", "Unable to write to the output file. Please check the permissions of the file.")
        return

    # 패딩된 데이터 표시
    output_text.config(state=tk.NORMAL)
    output_text.delete("1.0", tk.END)  # 이전 출력을 지웁니다.
    for i in range(0, len(padded_data), bytes_per_line):
        line = padded_data[i:i + bytes_per_line]
        address = i
        output_text.insert(tk.END, f'{address:08X}: ' + ' '.join(f'{byte:02X}' for byte in line) + '\n')
    output_text.config(state=tk.DISABLED)

    messagebox.showinfo("Done", f"Success File Save: {output_file}")


def select_input_file():
    file_path = filedialog.askopenfilename(title="Select Input File",
                                           filetypes=[("Binary, ELF and HEX files", "*.bin;*.elf;*.hex")])
    input_file_var.set(file_path)


def select_output_file():
    file_path = filedialog.asksaveasfilename(title="Select Output File", defaultextension=".bin",
                                             filetypes=[("Binary files", "*.bin")])
    output_file_var.set(file_path)


def run_padding():
    input_file = input_file_var.get()
    output_file = output_file_var.get()
    try:
        desired_size = int(desired_size_var.get()) if desired_size_var.get() else None
        bytes_per_line = int(bytes_per_line_var.get())
    except ValueError:
        messagebox.showerror("Error", "The number of bytes must be entered as an integer.")
        return

    if not input_file or not output_file:
        messagebox.showerror("Error", "You must select both input and output files.")
        return

    pad_firmware(input_file, output_file, desired_size, bytes_per_line)


# GUI 설정
root = tk.Tk()
root.title("Firmware Padding Tool")

# 입력 파일 선택
input_file_var = tk.StringVar()
tk.Label(root, text="Input File:").grid(row=0, column=0, padx=5, pady=5, sticky="e")
tk.Entry(root, textvariable=input_file_var, width=40).grid(row=0, column=1, padx=5, pady=5)
tk.Button(root, text="Search...", command=select_input_file).grid(row=0, column=2, padx=5, pady=5)

# 출력 파일 선택
output_file_var = tk.StringVar()
tk.Label(root, text="Output File:").grid(row=1, column=0, padx=5, pady=5, sticky="e")
tk.Entry(root, textvariable=output_file_var, width=40).grid(row=1, column=1, padx=5, pady=5)
tk.Button(root, text="Search...", command=select_output_file).grid(row=1, column=2, padx=5, pady=5)

# 원하는 파일 크기
desired_size_var = tk.StringVar()
tk.Label(root, text="Total Size (bytes. option):").grid(row=2, column=0, padx=5, pady=5, sticky="e")
tk.Entry(root, textvariable=desired_size_var, width=10).grid(row=2, column=1, padx=5, pady=5, sticky="w")

# 한 줄에 표시할 바이트 수
bytes_per_line_var = tk.StringVar()
tk.Label(root, text="Carriage Return:").grid(row=3, column=0, padx=5, pady=5, sticky="e")
tk.Entry(root, textvariable=bytes_per_line_var, width=10).grid(row=3, column=1, padx=5, pady=5, sticky="w")

# 실행 버튼
tk.Button(root, text="Padding", command=run_padding).grid(row=4, column=0, columnspan=3, pady=10)

# 결과 출력 창에 스크롤바 추가
frame = tk.Frame(root)
frame.grid(row=5, column=0, columnspan=3, padx=5, pady=5, sticky="nsew")

scrollbar = tk.Scrollbar(frame)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

output_text = tk.Text(frame, width=60, height=20, wrap=tk.NONE, yscrollcommand=scrollbar.set)
output_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

scrollbar.config(command=output_text.yview)

# GUI 시작
root.mainloop()
