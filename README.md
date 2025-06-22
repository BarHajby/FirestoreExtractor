# 🔥 FirestoreExtractor - Penetration Testing tool for Firestore

**FirestoreExtractor** is a powerful black-box penetration testing tool designed to extract and enumerate data from **Google Firestore** databases exposed directly to frontend clients (e.g., via Firebase SDK in Flutter Web, React, etc). It supports both unauthenticated and authenticated access flows, allowing security researchers to identify misconfigured rules, perform collection discovery, and extract sensitive information in a stealthy and automated manner.

---

## 🚀 Features

- 🔍 **Collection Brute-Forcing** using a user-defined or built-in wordlist.
- 🕵️ **Dual-Mode Testing** (authenticated & unauthenticated Firestore access).
- 🧪 **Read & Write Permission Checks** for each discovered collection.
- 🧼 **Auto-cleanup** for temporary write tests to minimize footprint.
- 🧬 **Config Leak Detection** (e.g., `apikey`, `token`, `auth`, etc.).
- 🧰 **Burp Suite/ any other proxy tools compatibility** (optional for interception/logging).

---

## 🛠️ Requirements

- `Python 3.7+`
- `requests`
- `tabulate`
- `colorama`
- Optional: Burp Suite (for traffic inspection)

Install dependencies:
```bash
pip install -r requirements.txt
```

---

## ⚙️ Usage

```bash
python firestoreExtractor.py
```

You will be prompted for:

- ✅ Firestore project ID or full host URL
- ✅ Whether to use an **ID token** for authenticated testing
- ✅ Optional **wordlist path** for custom collection brute-forcing
- ✅ Whether to enable **BurpSuite proxying** (e.g., `127.0.0.1:8080`)

### Example:

```bash
python firestore_extractor.py

> Enter Firestore host (e.g., company-12345, company-example, etc.): 
> Provide ID token (or leave empty for anonymous): 
> Wordlist path (optional): ./collections.txt
> Use Burp proxy? (y/n): y
```

---

## 🧠 How It Works

FirestoreExtractor simulates real client-side behavior by interacting directly with the Firestore REST API. It:

1. Sends crafted requests to check if collections exist.
2. Determines read/write access by attempting safe document operations.
3. Searches for sensitive keywords in readable fields.
4. Optionally suggests **escalation** via WRITE permissions to 'users' collection.

---

## 📄 Output

- Lists all discovered collections and access levels:
  ```
  [+] Collection: users → [READ: ✅] [WRITE: ❌]
  [+] Collection: settings → [READ: ✅] [WRITE: ✅]
  ```
---

## ⚠️ Legal Disclaimer

This tool is provided for **educational and authorized security testing** purposes only. Unauthorized access to systems or data is illegal. The author assumes no liability for misuse or damage.

---

## 🙌 Contributing

Pull requests are welcome! Please follow the existing style and provide meaningful commit messages.

---

## 📬 Contact

For questions, issues, or consulting inquiries, reach out via DM.

---

## 📘 License

This project is licensed under the MIT License. See `LICENSE` for details.
