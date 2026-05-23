# SecureScan Pro Code Security Scanner

SecureScan Pro is a simple Flask web app that helps you find common security issues in code and files.

<img width="1904" height="914" alt="image" src="https://github.com/user-attachments/assets/2b9bc2f1-a8e3-48be-856c-5673530ba913" />

<img width="1894" height="909" alt="image" src="https://github.com/user-attachments/assets/bf936aa2-e838-46af-80d9-b1c78832d624" />

<img width="1898" height="881" alt="image" src="https://github.com/user-attachments/assets/33618c3d-dd41-4de5-844d-22c98dbb3feb" />




## What it does

- Scan uploaded files or pasted code
- Detect unsafe patterns in Python, JavaScript, PHP, and generic text
- Find risky constructs like `eval`, `exec`, shell commands, SQL injection patterns, and hardcoded secrets
- Give a risk score and grade
- Show helpful recommendations to fix issues
- Report file hashes and known suspicious signatures

## Why use it?

- Learn where your code may be insecure before sharing or deploying it
- Catch common mistakes fast, without installing a heavy security tool
- Use it with any editor: VS Code, Notepad, Sublime, or browser copy/paste
- Improve your code quality with instant feedback and easy-to-follow fixes
- Great for students, developers, and small teams who want a quick security check

## Run locally in VS Code

1. Open this project folder in VS Code.
2. Open the terminal inside VS Code: `Terminal > New Terminal`.
3. Create a Python virtual environment:

```powershell
python -m venv venv
```

4. Activate the environment:

```powershell
venv\Scripts\Activate.ps1
```

5. Install Flask:

```powershell
pip install flask
```

6. Run the app:

```powershell
python app.py
```

7. Open your browser and go to:

```text
http://localhost:5000
```

## Use it with any editor

If you are using another editor like Notepad, Sublime Text, Atom, or PyCharm:

- Save the file you want to scan.
- Open the app in your browser at `http://localhost:5000`.
- Upload the saved file.
- Or copy code from your editor and paste it into the scan editor.

## How to scan code

1. Open `http://localhost:5000` in your browser.
2. Choose one of these options:
   - Upload a file from your computer.
   - Paste code directly into the editor.
3. Optionally enter a filename to help the scanner detect the language.
4. Click `Scan`.
5. Review the results:
   - risk score and grade
   - number of critical/high/medium/low issues
   - recommendations for fixing problems

## Tips for VS Code users

- You can scan code from any file opened in VS Code.
- If you want to test one file quickly, copy the file contents and paste them into the web editor.
- Use `Save As` to export a snippet if you want to upload it instead of pasting.

## API usage (optional)

You can also send data directly to the app using the `/scan` endpoint.

### Scan code directly

Send JSON like this:

```json
{
  "code": "print(\"hello\")",
  "filename": "example.py"
}
```

### Upload a file

Send a request with `multipart/form-data` and include a `file` field.

### What the API returns

The response includes:

- `filename`
- `language`
- `score`
- `grade`
- `file_size`
- `line_count`
- `hashes`
- `known_malware`
- `stats`
- `findings`
- `recommendations`

## Project files

- `app.py` — the Flask app and scanning logic
- `templates/index.html` — the web interface
- `README.md` — this guide
