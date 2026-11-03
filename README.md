# Cybersecurity Daily Briefing

A scheduled news agent that gathers recent reporting across cybersecurity, cloud, AI security, data protection and privacy, identity, applications, software supply chains, operating systems, networks, cybercrime, and critical infrastructure. Gemini selects up to 30 important stories from as many as 100 candidates, prioritizing severity and broad impact. Stories affecting widely used products and services (such as Windows, Android, iOS, browsers, and messaging apps) are specially highlighted. The email reports the number of included stories by severity. Severity labels combine model assessment with explicit CVSS and incident evidence so a model's "Informational" label does not override a clearly stated critical/high vulnerability or incident. Story summaries and social drafts contain at least three sentences, separated by blank lines for readability and copy/paste. Social drafts avoid repeating the article headline, include relevant emojis and hashtags, and use source-based fallbacks when generated copy is too short.

## What it monitors

CISA Advisories, The Hacker News, BleepingComputer, Krebs on Security, Microsoft Security and MSRC, AWS Security, Google Security Blog and Project Zero, Cloudflare, Cisco Talos and PSIRT advisories, Unit 42, Mozilla Security, Chrome and Android security bulletins, Dark Reading, SecurityWeek, InfoSecurity Magazine, The Record, CyberScoop, Help Net Security, Security Affairs, SANS Internet Storm Center, NIST and the NVD, NSA News, Linux Kernel CVE Announcements, Ubuntu and Red Hat security notices, CERT/CC Vulnerability Notes, GitHub Security Advisories, Jason Haddix, and OWASP GenAI Security. The collector looks back 48 hours, removes duplicate links and previously sent stories (tracked for 30 days), ranks likely high-impact reports, and includes up to 30 selected stories with a direct source link in the email. Stories are ordered Critical, High, Medium, then lower severity; widely used products and services receive a visible everyday-impact marker. Severity is classified where supported by CVSS or explicit severity language, and defaults to Informational when no rating is available. GitHub Actions preserves the sent-story history in its cache. Feed failures are logged; coverage depends on feed availability and should not be considered exhaustive.

## Enable daily delivery

1. Put this project in a GitHub repository.
2. In the repository, open **Settings → Secrets and variables → Actions** and add these repository secrets:
   - `GMAIL_ADDRESS`: the Gmail account that will send the briefing.
   - `GMAIL_APP_PASSWORD`: a Google App Password for that account. Use an App Password, not your normal Gmail password; Google account 2-Step Verification must be enabled.
   - `GEMINI_API_KEY`: a Gemini API key for AI story selection and summarization.
3. Optionally add the `GEMINI_MODEL` repository variable to choose a different Gemini model; it defaults to `gemini-3.8-flash`.
4. Ensure GitHub Actions are enabled. The workflow is scheduled to send the email daily at **06:00 Nepal Time (00:13 UTC)**. Run it once from **Actions → Daily cybersecurity briefing → Run workflow** to test delivery.

The repository must be on GitHub for its scheduled workflow to run. GitHub schedule times are UTC and may be delayed during high-load periods, so delivery may be later than 06:00. The first manual run will also confirm the secrets and Gmail account are configured correctly.

## Run locally

Requires Python 3.10 or later. Install the dependencies and set the environment variables listed in `.env.example` in your shell, then run:

```powershell
python -m pip install -r requirements.txt
python cybersec_digest.py
```

The Gemini key is optional at runtime: without it, the email includes ranked source excerpts and template LinkedIn/Meta drafts. When Gemini omits a social draft for an individual story, the agent fills it with a source-based template. Gmail sender and App Password are required to send any email. Feed and AI failures are logged; AI failures fall back to source excerpts without generic "review the original report" filler. Check the GitHub Actions run log for the exact Gemini error if the fallback is used (for example, authentication, quota/rate limits, network errors, or a malformed response). Review generated summaries and social copy against each linked source before posting.