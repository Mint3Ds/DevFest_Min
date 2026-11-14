# Suspicious Message Checker

A production-ready, zero-downtime web application built with **FastAPI**, **Tailwind CSS**, and **Google Gemini** (`google-genai`) that inspects suspicious texts, emails, or alerts for phishing, smishing, and social engineering warning signs.

## Features

- **Annotated Message Inspector**: Highlights every detected `exact_quote` verbatim inside the submitted message using category-coded badges (`Manufactured Urgency`, `Suspicious Link`, `Credential Request`, `Unofficial Channel`, `Social Engineering`) and plain-English explanations.
- **Interactive Verification Checklist**: Provides 3–4 concrete "How to Check Safely Before Acting" steps with checkboxes users can tick off before replying or clicking anything.
- **3-Tier Zero-Downtime Cascade**:
  1. **Deterministic Heuristic Scanner**: Regex/heuristic pre-scan detecting URL shorteners (`bit.ly`, `tinyurl.com`), lookalike domains, free consumer email addresses impersonating brands, OTP/password/2FA requests, remote access tools (`AnyDesk`, `TeamViewer`), gift cards/crypto, and urgent account-freeze threats.
  2. **Gemini Structured Analysis**: Calls Gemini via `google-genai` (`max_output_tokens=700`, `temperature=0.1`, `response_schema=AnalysisResponse`) with automatic fallback (`gemini-2.5-flash` -> `gemini-2.5-flash-lite` -> `gemini-3.5-flash-lite`).
  3. **Seamless Deterministic Fallback**: Falls back cleanly to `Deterministic Heuristic Mode` if API quota is exceeded, models fail, or `GEMINI_API_KEY` is omitted.
- **Quota & Abuse Protection**:
  - **1,500-character input cap** to prevent token exhaustion.
  - **In-memory SHA-256 response cache** keyed on normalized `(message, claimed_sender)` for zero-API repeat lookups.
  - **Per-IP sliding-window rate limiter** (10 requests/minute per IP; falls back to deterministic scanning rather than failing).

## Local Setup

1. Copy the environment template and set your API key:
   ```bash
   cp .env.example .env
   ```
   Edit `.env` and add `GEMINI_API_KEY=...` (`.env` is gitignored and never committed).

2. Install dependencies and start the server:
   ```bash
   pip install -r requirements.txt
   uvicorn main:app --host 0.0.0.0 --port 8080 --reload
   ```

3. Open `http://localhost:8080` in your browser.

## Deploy to Google Cloud Run (GitHub Continuous Deployment)

1. Open [Google Cloud Run — Create Service](https://console.cloud.google.com/run/create).
2. Select **Continuously deploy from a repository (Source or Function)** and click **Set up with Cloud Build**.
3. Connect GitHub repository **`Mint3Ds/DevFest_Min`** and set:
   - **Branch**: `^main$`
   - **Build Type**: `Dockerfile`
   - **Source location**: `/Dockerfile`
4. Set **Container port** to `8080`.
5. Under **Authentication**, select **Allow public access**.
6. Under **Container(s), Volumes, Networking, Security** -> **Variables & Secrets**, add:
   - Name: `GEMINI_API_KEY`
   - Value: your Gemini API key (or reference a Secret Manager secret).
7. Click **Create** to build and deploy.
