import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from PyPDF2 import PdfReader
from fpdf import FPDF
from transformers import pipeline, AutoTokenizer, AutoModelForCausalLM
import threading
import unicodedata

# Load LLM model and tokenizer
model_name = "gpt2"
tokenizer = AutoTokenizer.from_pretrained(model_name)
tokenizer.pad_token = tokenizer.eos_token
model = AutoModelForCausalLM.from_pretrained(model_name)
generator = pipeline("text-generation", model=model, tokenizer=tokenizer, device=-1)


def extract_urls_from_pdf(pdf_path):
    """Extract crawling URLs from the PDF."""
    urls = []
    reader = PdfReader(pdf_path)
    for page in reader.pages:
        text = page.extract_text()
        if "Crawling Information" in text:
            lines = text.split("\n")
            start_index = lines.index("Crawling Information") + 1
            for line in lines[start_index:]:
                if line.startswith("http://") or line.startswith("https://"):
                    urls.append(line.strip())
    return urls


def sanitize_text(text):
    """Replace unsupported characters with closest equivalents."""
    return unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode("ascii")


def write_response_to_pdf(response, output_pdf_path):
    """Save the sanitized response to a new PDF."""
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    sanitized_response = sanitize_text(response)
    pdf.multi_cell(0, 10, sanitized_response)
    pdf.output(output_pdf_path)


def process_with_llm(selected_url, progress, complete_callback):
    """Run LLM processing in a separate thread."""
    try:
        progress.start()
        prompt = (
            f"Analyze the URL {selected_url}  for malware type, attack vectors, system vulnerabilities, mitigation strategies, incident response, and long-term security best practices, providing a comprehensive security assessment report with technical depth and real-world example.Also, give the mitigation steps in points in the end."
        )
        responses = generator(prompt, max_length=1000, truncation=True, num_return_sequences=1)
        response_text = responses[0]["generated_text"].strip()
        progress.stop()
        complete_callback(response_text)
    except Exception as e:
        progress.stop()
        messagebox.showerror("Error", f"Error during LLM processing: {e}")


def on_submit():
    """Handle the submit button click."""
    selected_url = url_var.get()
    if not selected_url:
        messagebox.showerror("Error", "Please select a URL!")
        return

    progress_bar.pack(pady=10)
    submit_button.config(state=tk.DISABLED)

    def on_complete(response):
        progress_bar.pack_forget()
        submit_button.config(state=tk.NORMAL)
        output_pdf_path = filedialog.asksaveasfilename(
            title="Save Response As",
            defaultextension=".pdf",
            filetypes=[("PDF files", "*.pdf")]
        )
        if output_pdf_path:
            write_response_to_pdf(response, output_pdf_path)
            messagebox.showinfo("Success", f"Response saved to {output_pdf_path}")

    threading.Thread(target=process_with_llm, args=(selected_url, progress_bar, on_complete)).start()


def select_pdf():
    """Allow user to select a PDF file dynamically."""
    pdf_path = filedialog.askopenfilename(
        title="Select a PDF file",
        filetypes=[("PDF files", "*.pdf")]
    )
    if pdf_path:
        try:
            urls = extract_urls_from_pdf(pdf_path)
            if urls:
                url_dropdown.config(values=urls)
                url_dropdown.set("")  # Clear the selection
                messagebox.showinfo("Success", "URLs extracted successfully!")
            else:
                messagebox.showerror("Error", "No URLs found in the PDF.")
        except Exception as e:
            messagebox.showerror("Error", f"Error processing PDF: {e}")


# Create main GUI
root = tk.Tk()
root.title("URL Analyzer")
root.geometry("600x400")

tk.Label(root, text="Upload a PDF and Select a URL:", font=("Arial", 14)).pack(pady=10)

# Button to select PDF file
upload_button = tk.Button(root, text="Upload PDF", command=select_pdf, font=("Arial", 12))
upload_button.pack(pady=10)

# Dropdown to display extracted URLs
url_var = tk.StringVar()
url_dropdown = ttk.Combobox(root, textvariable=url_var, state="readonly", width=50)
url_dropdown.pack(pady=10)

# Submit button to process selected URL
submit_button = tk.Button(root, text="Submit", command=on_submit, font=("Arial", 12))
submit_button.pack(pady=10)

# Progress bar
progress_bar = ttk.Progressbar(root, orient="horizontal", mode="indeterminate", length=300)

# Start the GUI loop
root.mainloop()
