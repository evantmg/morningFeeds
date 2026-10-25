# Cybersecurity Daily Briefing

A scheduled news agent that gathers recent reporting across cybersecurity, cloud, AI security, data protection and privacy, identity, applications, software supply chains, networks, and critical infrastructure. Gemini prioritizes stories and prepares summaries, key points, source links, and separate professional LinkedIn and punchy, lightly witty Meta drafts for each selected update.

## What it monitors

CISA advisories, The Hacker News, BleepingComputer, Krebs on Security, Microsoft Security, AWS Security, Google Security Blog, Cloudflare, Cisco Talos, Unit 42, Dark Reading, SecurityWeek, InfoSecurity Magazine, SANS Internet Storm Center, NIST, NSA News, Jason Haddix, and OWASP GenAI Security. The collector looks back 48 hours, removes duplicate links, ranks likely high-impact reports, and includes up to 8 selected stories with a direct source link in the email. CISA's feed may be inaccessible from some networks; feed failures are logged.

## Enable daily delivery

1. Put this project in a GitHub repository.
2. In the repository, open **Settings → Secrets and variables → Actions** and add these repository secrets:
   - `GMAIL_ADDRESS`: the Gmail account that will send the briefing.
   - `GMAIL_APP_PASSWORD`: a Google App Password for that account. Use an App Password, not your normal Gmail password; Google account 2-Step Verification must be enabled.
   - `GEMINI_API_KEY`: a Gemini API key for AI story selection and summarization.
3. Optionally add the `GEMINI_MODEL` repository variable to choose a different Gemini model; it defaults to `gemini-3.8-flash`.
4. Ensure GitHub Actions are enabled. The workflow sends the email daily at **08:00 UTC**. Run it once from **Actions → Daily cybersecurity briefing → Run workflow** to test delivery.

The repository must be on GitHub for its scheduled workflow to run. GitHub schedule times are UTC and may be delayed during high-load periods. The first manual run will also confirm the secrets and Gmail account are configured correctly.

## Run locally

Requires Python 3.10 or later. Install the dependencies and set the environment variables listed in `.env.example` in your shell, then run:

```powershell
python -m pip install -r requirements.txt
python cybersec_digest.py
```

The Gemini key is optional at runtime: without it, the email includes ranked source excerpts but not AI-generated highlights or social drafts. Gmail sender and App Password are required to send any email. Feed and AI failures are logged; AI failures fall back to source excerpts. Review AI-generated facts and social copy against each linked source before posting.