# 🛡️ AI Scam Detector

An AI-powered application that analyzes suspicious SMS messages and emails using the Google Gemini API. It identifies potential scam indicators, assigns a risk score, explains red flags in simple language, and recommends what the user should do next.

## 🚀 Features

- **Scam Classification:** Classifies messages as `SCAM`, `SUSPICIOUS`, or `SAFE`.
- **Risk Scoring:** Assigns a risk score from 0 to 100.
- **Scam Type Detection:** Identifies categories such as phishing, fake delivery, bank impersonation, lottery/prize scams, job scams, and more.
- **Fraud Pattern Detection:** Checks for urgency, payment requests, credential-related words, and shortened URLs.
- **Red Flag Identification:** Highlights suspicious evidence in the message.
- **Simple Explanations:** Explains potential risks in easy-to-understand language.
- **Recommended Actions:** Suggests a safer next step.
- **Streamlit Interface:** Provides a simple web interface for analyzing SMS and email messages.
- **JSON Validation and Retries:** Validates the AI response and retries when the output is invalid or an API error occurs.
- **Sample Messages:** Includes built-in examples for testing the command-line version.

## 🧰 Tech Stack

- Python
- Streamlit
- Google Gemini API
- Google Gen AI SDK
- JSON
- Regular Expressions

## ⚙️ How It Works

1. **User Input:** The user selects SMS or Email and enters a message.
2. **Rule-Based Pre-Check:** The application checks for urgency-related words, payment terms, credential-related terms, shortened URLs, and links.
3. **Prompt Engineering:** The message and pre-check signals are passed to Gemini with instructions to return a structured JSON response.
4. **AI Analysis:** Gemini identifies the likely verdict, risk score, scam type, intent, fraud patterns, and red flags.
5. **Response Validation:** The application parses the JSON, checks required fields, validates the verdict, and constrains the risk score to the 0–100 range.
6. **Results Display:** The application displays the verdict, risk score, explanation, red flags, and recommended action.

## 📁 Project Structure

```text
AI-Scam-Detector/
│
├── app.py
├── scam_detector_gemini.py
├── requirements.txt
└── README.md
```

- `app.py` — Streamlit web interface.
- `scam_detector_gemini.py` — Prompt engineering, rule-based checks, Gemini API integration, JSON parsing, validation, and analysis logic.
- `requirements.txt` — Python dependencies.
- `README.md` — Project documentation.

## 🛠️ Installation and Setup

### 1. Clone the Repository

```bash
git clone YOUR_REPOSITORY_URL
cd AI-Scam-Detector
```

Replace `YOUR_REPOSITORY_URL` with your GitHub repository URL.

### 2. Create a Virtual Environment (Optional)

```bash
python -m venv venv
```

Activate it on Windows:

```bash
venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

If you do not have a `requirements.txt` file yet, install the required packages:

```bash
pip install streamlit google-genai
```

### 4. Configure the Gemini API Key

Get an API key from [Google AI Studio](https://aistudio.google.com/apikey).

**Windows Command Prompt:**

```cmd
set GEMINI_API_KEY=your_api_key_here
```

**Windows PowerShell:**

```powershell
$env:GEMINI_API_KEY="your_api_key_here"
```

**macOS/Linux:**

```bash
export GEMINI_API_KEY="your_api_key_here"
```

Never upload your actual API key to GitHub.

## ▶️ Run the Application

### Web Application

```bash
streamlit run app.py
```

Open the local URL shown in your terminal, select the message type, paste a sample message, and click **Check message**.

### Command-Line Version

Run the built-in sample messages:

```bash
python scam_detector_gemini.py
```

Analyze your own messages interactively:

```bash
python scam_detector_gemini.py --chat
```

## 📊 Example Output

```text
🚨 SCAM (risk 92/100)

Type: fake delivery

Intent: Get the reader to pay a fee and enter card details.

Patterns:
- urgency
- suspicious link
- request for money

Red flags:
- Shortened or suspicious link
- Tight deadline
- Request for payment

In simple terms:
The message may be trying to pressure the recipient into
paying through a suspicious website.

What to do:
Do not click the link. Verify the delivery through the
courier's official website or application.
```

*Example output is illustrative; actual results depend on the message and the model's response.*

## 🔐 Security and Privacy

- Do not test with real passwords, OTPs, bank details, or other sensitive personal information.
- Use sample or fictional messages for testing.
- Keep your Gemini API key in an environment variable or Streamlit Secrets.
- Do not click suspicious links or call phone numbers contained in potentially fraudulent messages.
- Review messages through official channels when verification is needed.

## ⚠️ Limitations

- AI classifications may be incorrect. A `SAFE` verdict does not guarantee that a message is legitimate.
- Rule-based keyword checks can miss unfamiliar scam patterns or flag harmless messages.
- Results depend on the quality of the input and the Gemini model's output.
- API availability, rate limits, and usage quotas may affect analysis.
- This project is an educational tool, not a replacement for professional fraud detection or official security checks.

## 🎯 Learning Outcomes

This project helped explore:

- Prompt engineering for structured LLM outputs.
- Integrating an LLM API into a Python application.
- Combining rule-based checks with AI analysis.
- JSON parsing and response validation.
- Retry and error-handling logic.
- Building an interactive Streamlit application.
- Communicating AI-generated risk assessments clearly.

## 👨‍💻 Author

**Satheesh Kumar Arigela**

- **GitHub:** [SatheeshkumarArigela](https://github.com/SatheeshkumarArigela)
- **LinkedIn:** [Arigela Satheesh Kumar](https://www.linkedin.com/in/arigela-satheesh-kumar-59a00822b/)
