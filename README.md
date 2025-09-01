# 🔐 Universal Cipher Translator

A powerful web app for encrypting messages and automatically decrypting ciphers.

## Features

### 🔓 Decrypt Mode
- **Auto-detection** of Caesar and Vigenère ciphers
- **Smart analysis** using English word matching
- **Multiple candidates** when confidence is low
- **Example ciphers** to test with

### 🔒 Encrypt Mode  
- **Caesar Cipher** with custom shift amounts
- **ROT13** one-click encoding
- **Vigenère Cipher** with custom keys
- **Live preview** as you type

## How to Use

1. **Decrypt**: Paste encrypted text → click "Decrypt" → get results
2. **Encrypt**: Type message → choose method → copy result

## Deployment

### Local
```bash
pip install streamlit
streamlit run cipher_solver_app.py
```

### Streamlit Cloud
1. Upload to GitHub
2. Deploy at [share.streamlit.io](https://share.streamlit.io)
3. Share the URL!

## Files
- `cipher_solver_app.py` - Main Streamlit application
- `words.txt` - English dictionary for word matching
- `requirements.txt` - Python dependencies

## Examples

**Caesar Cipher (Shift 7):**
- Plain: `Good morning asshole`
- Encrypted: `Nvvk tvyupun hzzovsl`

**ROT13:**
- Plain: `Hello World`  
- Encrypted: `Uryyb Jbeyq`

**Vigenère (Key: "SECRET"):**
- Plain: `Attack at dawn`
- Encrypted: `Sxvseh ex qeir`

---

Built with ❤️ using Streamlit
