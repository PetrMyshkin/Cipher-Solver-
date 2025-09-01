import streamlit as st
import re
import string

# --- Load wordlist (no nltk needed) ---
@st.cache_data
def load_wordlist(path="words.txt"):
    try:
        with open(path, "r") as f:
            return set(w.strip().lower() for w in f if w.strip())
    except FileNotFoundError:
        # Minimal fallback if words.txt not found
        return {
            "the","be","to","of","and","a","in","that","have","i","it","for","not",
            "on","with","he","as","you","do","at","this","but","his","by","from",
            "they","we","say","her","she","or","an","will","my","one","all","would",
            "there","their","what","so","up","out","if","about","who","get","which",
            "go","me","when","make","can","like","time","no","just","him","know","take",
            "person","into","year","your","good","some","could","them","see","other",
            "than","then","now","look","only","come","its","over","think","also","back",
            "after","use","two","how","our","work","first","well","way","even","new",
            "want","because","any","these","give","day","most","us","hello","world",
            "morning","fast","was","asshole","secret","message","code","cipher"
        }

english_words = load_wordlist()

# --- ENCRYPTION FUNCTIONS ---
def caesar_encrypt(plaintext, shift):
    ciphertext = ""
    for char in plaintext:
        if char.isalpha():
            offset = 65 if char.isupper() else 97
            ciphertext += chr((ord(char) - offset + shift) % 26 + offset)
        else:
            ciphertext += char
    return ciphertext

def vigenere_encrypt(plaintext, key):
    ciphertext = ""
    key_len = len(key)
    key_as_int = [ord(i.lower()) - ord('a') for i in key]

    for i, char in enumerate(plaintext):
        if char.isalpha():
            offset = 65 if char.isupper() else 97
            shift = key_as_int[i % key_len]
            ciphertext += chr((ord(char) - offset + shift) % 26 + offset)
        else:
            ciphertext += char
    return ciphertext

# --- DECRYPTION FUNCTIONS ---
def caesar_decrypt(ciphertext, shift):
    plaintext = ""
    for char in ciphertext:
        if char.isalpha():
            offset = 65 if char.isupper() else 97
            plaintext += chr((ord(char) - offset - shift) % 26 + offset)
        else:
            plaintext += char
    return plaintext

def vigenere_decrypt(ciphertext, key):
    plaintext = ""
    key_len = len(key)
    key_as_int = [ord(i.lower()) - ord('a') for i in key]

    for i, char in enumerate(ciphertext):
        if char.isalpha():
            offset = 65 if char.isupper() else 97
            shift = key_as_int[i % key_len]
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
        return "Caesar", candidates[:3]  # Return top 3 candidates
    return None, None

def analyze_vigenere(ciphertext, min_matches=2):
    candidates = []
    common_keys = ["key","love","code","secret","cipher","cat","dog","test","abc","xyz",
                   "password","hello","world","crypto","decode","solve"]

    for key_str in common_keys:
        candidate = vigenere_decrypt(ciphertext, key_str).lower()
        words_in_candidate = re.findall(r"[a-z]+", candidate)
        matches = sum(1 for w in words_in_candidate if w in english_words)
        if matches >= min_matches:
            candidates.append((key_str, candidate, matches))

    candidates.sort(key=lambda x: -x[2])
    if candidates:
        return "Vigenere", candidates[:3]  # Return top 3 candidates
    return None, None

# --- MAIN APP ---
def main():
    st.set_page_config(
        page_title="Cipher Translator",
        page_icon="🔐",
        layout="wide"
    )

    st.title("🔐 Universal Cipher Translator")
    st.markdown("**Encrypt messages or decrypt ciphers automatically**")

    # Create tabs
    tab1, tab2 = st.tabs(["🔓 Decrypt Cipher", "🔒 Encrypt Message"])

    # --- DECRYPT TAB ---
    with tab1:
        st.header("🔍 Cipher Solver")
        st.markdown("Paste encrypted text and let the AI figure out what cipher it is!")

        # Sidebar examples for decrypt
        with st.sidebar:
            st.header("📝 Example Ciphers")
            decrypt_examples = {
                "Caesar (Shift 7)": "Nvvk tvyupun hzzovsl",
                "ROT13": "Uryyb Jbeyq",
                "Caesar (Shift 3)": "Wkdw zdv idvw",
                "Vigenère (key)": "Danzq iqhnh"
            }

            for name, example in decrypt_examples.items():
                if st.button(f"Try: {name}"):
                    st.session_state.decrypt_input = example

        # Decrypt input
        decrypt_input = st.text_area(
            "Enter encrypted text:",
            value=st.session_state.get('decrypt_input', ''),
            height=100,
            placeholder="Nvvk tvyupun hzzovsl",
            key="decrypt_area"
        )

        # Decrypt settings
        col1, col2 = st.columns(2)
        with col1:
            min_matches = st.slider("Minimum word matches", 1, 5, 2)
        with col2:
            show_all_attempts = st.checkbox("Show all attempts", value=False)

        # Solve button
        if st.button("🔍 Decrypt", type="primary"):
            if decrypt_input.strip():
                with st.spinner("Analyzing cipher..."):
                    # Try Caesar
                    cipher_type, caesar_results = analyze_caesar(decrypt_input.strip(), min_matches)
                    if cipher_type == "Caesar":
                        st.success("✅ **Caesar Cipher Detected!**")

                        # Show best result prominently
                        best = caesar_results[0]
                        shift, candidate, matches = best
                        st.markdown("### 📄 Decrypted Text:")
                        st.code(candidate, language=None)

                        col1, col2 = st.columns(2)
                        with col1:
                            st.info(f"🔧 **Method:** Caesar Shift {shift}")
                        with col2:
                            st.info(f"📊 **Confidence:** {matches} words matched")

                        if show_all_attempts and len(caesar_results) > 1:
                            st.markdown("#### Other possible decryptions:")
                            for shift, candidate, matches in caesar_results[1:]:
                                st.text(f"Shift {shift}: {candidate} ({matches} matches)")

                    # Try Vigenère if Caesar failed
                    elif True:
                        cipher_type, vigenere_results = analyze_vigenere(decrypt_input.strip(), min_matches)
                        if cipher_type == "Vigenere":
                            st.success("✅ **Vigenère Cipher Detected!**")

                            best = vigenere_results[0]
                            key, candidate, matches = best
                            st.markdown("### 📄 Decrypted Text:")
                            st.code(candidate, language=None)

                            col1, col2 = st.columns(2)
                            with col1:
                                st.info(f"🔧 **Method:** Vigenère Key '{key}'")
                            with col2:
                                st.info(f"📊 **Confidence:** {matches} words matched")

                            if show_all_attempts and len(vigenere_results) > 1:
                                st.markdown("#### Other possible decryptions:")
                                for key, candidate, matches in vigenere_results[1:]:
                                    st.text(f"Key '{key}': {candidate} ({matches} matches)")
                        else:
                            st.error("⚠️ Could not decrypt using known methods")
                            st.info("💡 Try a different cipher type, longer key, or manual analysis")
            else:
                st.warning("Please enter some encrypted text to analyze.")

    # --- ENCRYPT TAB ---
    with tab2:
        st.header("🔒 Message Encoder")
        st.markdown("Create secret messages using various cipher methods!")

        # Encrypt input
        encrypt_input = st.text_area(
            "Enter message to encrypt:",
            value="Hello World",
            height=100,
            placeholder="Type your secret message here...",
            key="encrypt_area"
        )

        # Cipher method selection
        cipher_method = st.selectbox(
            "Choose encryption method:",
            ["Caesar Cipher", "ROT13", "Vigenère Cipher"]
        )

        # Method-specific settings
        if cipher_method == "Caesar Cipher":
            shift = st.slider("Caesar shift amount:", 1, 25, 7)
            if encrypt_input:
                encrypted = caesar_encrypt(encrypt_input, shift)
                st.markdown("### 🔒 Encrypted Result:")
                st.code(encrypted, language=None)
                st.caption(f"Used Caesar cipher with shift {shift}")

        elif cipher_method == "ROT13":
            if encrypt_input:
                encrypted = caesar_encrypt(encrypt_input, 13)
                st.markdown("### 🔒 Encrypted Result:")
                st.code(encrypted, language=None)
                st.caption("Used ROT13 (Caesar shift 13)")

        elif cipher_method == "Vigenère Cipher":
            vigenere_key = st.text_input("Vigenère key:", value="SECRET", placeholder="Enter key word")
            if encrypt_input and vigenere_key:
                encrypted = vigenere_encrypt(encrypt_input, vigenere_key)
                st.markdown("### 🔒 Encrypted Result:")
                st.code(encrypted, language=None)
                st.caption(f"Used Vigenère cipher with key '{vigenere_key}'")

        # Quick encrypt examples
        st.markdown("#### 🎯 Quick Examples:")
        col1, col2, col3 = st.columns(3)

        with col1:
            if st.button("Caesar (shift 3)"):
                st.session_state.encrypt_input = "The quick brown fox"
                st.session_state.cipher_method = "Caesar Cipher"
                st.rerun()

        with col2:
            if st.button("ROT13 Classic"):
                st.session_state.encrypt_input = "Secret message"
                st.session_state.cipher_method = "ROT13"
                st.rerun()

        with col3:
            if st.button("Vigenère (KEY)"):
                st.session_state.encrypt_input = "Top secret"
                st.session_state.cipher_method = "Vigenère Cipher"
                st.rerun()

    # Footer
    st.markdown("---")
    st.markdown("**💡 Pro tip:** Encrypt a message here, then test it in the Decrypt tab to see if the AI can crack it!")

if __name__ == "__main__":
    main()
