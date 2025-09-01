
import streamlit as st
import re
import nltk
from collections import Counter

# Download required NLTK data (only runs once)
@st.cache_resource
def download_nltk_data():
    try:
        nltk.data.find('corpora/words')
    except LookupError:
        nltk.download('words', quiet=True)
    return True

download_nltk_data()
from nltk.corpus import words
english_words = set(w.lower() for w in words.words())

# --- Caesar Decryption ---
def caesar_decrypt(ciphertext, shift):
    plaintext = ""
    for char in ciphertext:
        if char.isalpha():
            offset = 65 if char.isupper() else 97
            plaintext += chr((ord(char) - offset - shift) % 26 + offset)
        else:
            plaintext += char
    return plaintext

def analyze_caesar(ciphertext, min_matches=2):
    candidates = []
    for shift in range(1, 26):
        candidate = caesar_decrypt(ciphertext, shift).lower()
        words_in_candidate = re.findall(r"[a-z]+", candidate)
        matches = sum(1 for w in words_in_candidate if w in english_words)
        candidates.append((shift, candidate, matches))

    candidates.sort(key=lambda x: (-x[2], x[0]))
    if candidates and candidates[0][2] >= min_matches:
        return "Caesar", candidates[0]
    return None, None

# --- Vigenère Decryption ---
def vigenere_decrypt(ciphertext, key):
    plaintext = ""
    key_len = len(key)
    key_as_int = [ord(i) for i in key.lower()]

    for i, char in enumerate(ciphertext):
        if char.isalpha():
            offset = 65 if char.isupper() else 97
            shift = key_as_int[i % key_len] - ord('a')
            plaintext += chr((ord(char) - offset - shift) % 26 + offset)
        else:
            plaintext += char
    return plaintext

def analyze_vigenere(ciphertext, min_matches=2):
    best_vigenere_candidate = None
    best_vigenere_matches = -1

    # Common short keys to try
    common_keys = ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z",
                   "key", "love", "code", "secret", "cipher", "cat", "dog", "test", "abc", "xyz"]

    for key_str in common_keys:
        candidate = vigenere_decrypt(ciphertext, key_str).lower()
        words_in_candidate = re.findall(r"[a-z]+", candidate)
        matches = sum(1 for w in words_in_candidate if w in english_words)

        if matches > best_vigenere_matches:
            best_vigenere_matches = matches
            best_vigenere_candidate = (key_str, candidate, matches)

    if best_vigenere_candidate and best_vigenere_matches >= min_matches:
        return "Vigenere", best_vigenere_candidate
    return None, None

# --- Main Solver ---
def solve_cipher(ciphertext):
    results = []

    # 1. Try Caesar
    cipher_type, caesar_result = analyze_caesar(ciphertext)
    if cipher_type == "Caesar":
        shift, candidate, matches = caesar_result
        results.append({
            "type": "Caesar Cipher",
            "details": f"Shift {shift}",
            "result": candidate,
            "confidence": f"{matches} English words matched"
        })
        return results

    # 2. Try Vigenère
    cipher_type, vigenere_result = analyze_vigenere(ciphertext)
    if cipher_type == "Vigenere":
        key, candidate, matches = vigenere_result
        results.append({
            "type": "Vigenère Cipher",
            "details": f"Key: '{key}'",
            "result": candidate,
            "confidence": f"{matches} English words matched"
        })
        return results

    # 3. No match found
    results.append({
        "type": "Unknown",
        "details": "No confident match found",
        "result": "Could not decrypt using Caesar or Vigenère with common keys",
        "confidence": "Try a different cipher type or longer key"
    })
    return results

# --- Streamlit UI ---
def main():
    st.set_page_config(
        page_title="Universal Cipher Solver",
        page_icon="🔐",
        layout="wide"
    )

    st.title("🔐 Universal Cipher Solver")
    st.markdown("**Automatically detect and solve Caesar and Vigenère ciphers**")

    # Sidebar with examples
    st.sidebar.header("📝 Try These Examples")
    examples = {
        "Caesar Cipher": "Nvvk tvyupun hzzovsl",
        "ROT13": "Uryyb Jbeyq",
        "Vigenère": "Rijvs uyvjn",
        "Another Caesar": "Aoha dhz mhza"
    }

    for name, example in examples.items():
        if st.sidebar.button(f"{name}"):
            st.session_state.cipher_input = example

    # Main input
    cipher_input = st.text_area(
        "Enter encrypted text:",
        value=st.session_state.get('cipher_input', ''),
        height=100,
        placeholder="Paste your encrypted message here..."
    )

    # Settings
    col1, col2 = st.columns(2)
    with col1:
        min_matches = st.slider("Minimum word matches for confidence", 1, 5, 2)
    with col2:
        show_details = st.checkbox("Show technical details", value=True)

    # Solve button
    if st.button("🔍 Solve Cipher", type="primary"):
        if cipher_input.strip():
            with st.spinner("Analyzing cipher..."):
                results = solve_cipher(cipher_input.strip())

                for result in results:
                    if result["type"] == "Unknown":
                        st.error(f"⚠️ {result['result']}")
                        st.info(f"💡 {result['confidence']}")
                    else:
                        st.success(f"✅ **{result['type']} Detected!**")

                        # Show the decrypted result prominently
                        st.markdown("### 📄 Decrypted Text:")
                        st.code(result["result"], language=None)

                        if show_details:
                            col1, col2 = st.columns(2)
                            with col1:
                                st.info(f"🔧 **Method:** {result['details']}")
                            with col2:
                                st.info(f"📊 **Confidence:** {result['confidence']}")
        else:
            st.warning("Please enter some encrypted text to analyze.")

    # Footer
    st.markdown("---")
    st.markdown("**How it works:** This tool tries Caesar shifts (1-25) and common Vigenère keys to find English text.")

if __name__ == "__main__":
    main()
