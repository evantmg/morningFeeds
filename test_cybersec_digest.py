import json
import os
import re
import unittest
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import patch

from cybersec_digest import (
    FEEDS,
    MAX_DIGEST_STORIES,
    Story,
    build_email,
    clean_editorial_text,
    create_social_post,
    everyday_impact_label,
    fallback_digest,
    infer_severity,
    normalize_severity,
    remove_repeated_headline,
    summarize_stories,
)


class DigestRegressionTests(unittest.TestCase):
    def test_removes_headline_repeated_at_start_of_social_post(self):
        headline = "Google Disrupts 1.3 Million-Device Android Botnet"
        post = (
            f"⚡ {headline}\n\n"
            "Google says the device maker deliberately enabled criminal access."
        )

        self.assertEqual(
            remove_repeated_headline(headline, post),
            "⚡ Google says the device maker deliberately enabled criminal access.",
        )

    def test_keeps_social_post_when_it_does_not_repeat_headline(self):
        post = "A new flaw is being exploited in the wild."
        self.assertEqual(
            remove_repeated_headline("Linux kernel flaw patched", post),
            post,
        )

    def test_fallback_social_posts_include_the_story_summary_without_title(self):
        story = Story(
            title="A serious security update",
            url="https://example.com/security-update",
            source="Example",
            published="2026-11-02T00:00:00+00:00",
            excerpt=(
                "The vendor fixed a remotely exploitable flaw affecting supported "
                "devices. Administrators should install the update promptly."
            ),
            score=5,
            topics=["Threats & Vulnerabilities"],
        )

        result = fallback_digest([story])["stories"][0]

        self.assertEqual(result["severity"], "Informational")
        summary_body = result["summary"]
        self.assertGreaterEqual(len(re.findall(r"[.!?](?:\s|$)", summary_body)), 3)
        self.assertGreaterEqual(len(summary_body.split("\n\n")), 3)
        for platform in ("linkedin_post", "meta_post"):
            self.assertIn("The vendor fixed", result[platform])
            self.assertNotIn(story.title, result[platform])
            self.assertIn(story.url, result[platform])
            self.assertGreaterEqual(
                len(re.findall(r"[.!?](?:\s|$)", result[platform].split("\n\n#")[0])),
                3,
            )

    def test_social_posts_have_three_sentences_and_copy_friendly_spacing(self):
        post = create_social_post(
            "meta",
            "Android security issue disclosed",
            "Researchers found a backdoor in Android TV devices.",
            "Researchers found a backdoor in Android TV devices.",
            ["More than one million devices were affected."],
            "Google disrupted the command infrastructure.",
            "Android security issue botnet",
            "https://example.com/report",
        )

        body = post.split("\n\n#")[0]
        self.assertGreaterEqual(len(re.findall(r"[.!?](?:\s|$)", body)), 3)
        self.assertGreaterEqual(len(body.split("\n\n")), 3)
        self.assertIn("🚨", body)
        self.assertIn("#AndroidSecurity", post)
        self.assertIn("#CyberNews", post)
        self.assertTrue(post.endswith("https://example.com/report"))

    def test_removes_image_caption_and_accessibility_feed_artifacts(self):
        text = clean_editorial_text(
            "Google disrupted the botnet. XCPE malware overview (Source: Google) "
            "Access The business model was access."
        )

        self.assertEqual(text, "Google disrupted the botnet.")

    def test_severity_is_inferred_from_supported_evidence(self):
        self.assertEqual(infer_severity("Critical vulnerability, CVSS 9.8"), "Critical")
        self.assertEqual(infer_severity("Actively exploited RCE"), "High")
        self.assertEqual(infer_severity("CVSS 5.4 moderate vulnerability"), "Medium")
        self.assertEqual(infer_severity("CVSS 2.1 low vulnerability"), "Low")
        self.assertEqual(infer_severity("A new security research report"), "Informational")
        self.assertEqual(
            normalize_severity("Unassessed", "Actively exploited flaw"),
            "High",
        )

    def test_short_generated_posts_fall_back_without_repeating_headline(self):
        story = Story(
            title="Critical Linux kernel vulnerability actively exploited",
            url="https://example.com/kernel-cve",
            source="Example",
            published="2026-11-02T00:00:00+00:00",
            excerpt=(
                "A maximum-severity Linux kernel vulnerability is being actively exploited. "
                "The fix is available in the latest supported kernel update."
            ),
            score=10,
            topics=["Operating Systems & Endpoint"],
        )
        response = {
            "stories": [{
                "url": story.url,
                "summary": (
                    "A maximum-severity Linux kernel vulnerability is being actively exploited. "
                    "The fix is available in the latest supported kernel update."
                ),
                "highlights": ["The fix is available in the latest supported kernel update."],
                "severity": "Unassessed",
                "linkedin_post": f"⚠️ {story.title}",
                "meta_post": f"🚨 {story.title}",
            }],
        }
        client = SimpleNamespace(
            models=SimpleNamespace(
                generate_content=lambda **kwargs: SimpleNamespace(text=json.dumps(response))
            )
        )

        with patch.dict(os.environ, {"GEMINI_API_KEY": "test-key"}):
            with patch("cybersec_digest.genai.Client", return_value=client):
                result = summarize_stories([story])["stories"][0]

        self.assertEqual(result["severity"], "Critical")
        for platform in ("linkedin_post", "meta_post"):
            self.assertNotIn(story.title, result[platform])
            self.assertIn("A maximum-severity Linux kernel vulnerability", result[platform])

    def test_feed_catalog_covers_multiple_security_domains(self):
        self.assertIn("Linux Kernel CVE Announcements", FEEDS)
        self.assertIn("Ubuntu Security Notices", FEEDS)
        self.assertIn("Red Hat Security", FEEDS)
        self.assertIn("Mozilla Security Blog", FEEDS)
        self.assertIn("Android Security Bulletins", FEEDS)
        self.assertIn("Cisco Security Advisories", FEEDS)

    def test_digest_orders_by_severity_and_highlights_everyday_technology(self):
        stories = [
            {
                "title": "A medium severity Android issue",
                "url": "https://example.com/medium",
                "source": "Example",
                "published": "2026-11-02T00:00:00+00:00",
                "severity": "Medium",
                "summary": "A flaw affects Android devices.",
            },
            {
                "title": "A high severity server issue",
                "url": "https://example.com/high-server",
                "source": "Example",
                "published": "2026-11-02T00:00:00+00:00",
                "severity": "High",
                "summary": "A server flaw is being actively exploited.",
            },
            {
                "title": "A critical infrastructure issue",
                "url": "https://example.com/critical",
                "source": "Example",
                "published": "2026-11-02T00:00:00+00:00",
                "severity": "Critical",
                "summary": "A critical vulnerability affects a database server.",
            },
            {
                "title": "A high severity Chrome issue",
                "url": "https://example.com/high-chrome",
                "source": "Example",
                "published": "2026-11-02T00:00:00+00:00",
                "severity": "High",
                "summary": "A vulnerability affects the Chrome browser.",
            },
        ]

        _, text_body, html_body = build_email(
            {"topline": "Updates.", "stories": stories},
            datetime(2026, 11, 3, tzinfo=timezone.utc),
        )

        critical_position = text_body.index("[CRITICAL]")
        high_chrome_position = text_body.index("A high severity Chrome issue")
        high_server_position = text_body.index("A high severity server issue")
        medium_position = text_body.index("[MEDIUM]")
        self.assertLess(critical_position, high_chrome_position)
        self.assertLess(high_chrome_position, high_server_position)
        self.assertLess(high_server_position, medium_position)
        self.assertIn("EVERYDAY TECH IMPACT: Android", text_body)
        self.assertIn("EVERYDAY TECH IMPACT &mdash;", html_body)
        self.assertTrue(everyday_impact_label("A security flaw affects Chrome browser"))

    def test_digest_limit_allows_more_than_fifteen_stories(self):
        stories = [
            Story(
                title=f"Security report {index} describes a distinct incident",
                url=f"https://example.com/security-report-{index}",
                source="Example",
                published=f"2026-11-{(index % 28) + 1:02d}T00:00:00+00:00",
                excerpt=f"Researchers describe incident number {index} affecting customers.",
                score=1,
                topics=["Cybercrime & Incident Response"],
            )
            for index in range(MAX_DIGEST_STORIES + 1)
        ]

        result = fallback_digest(stories)

        self.assertGreater(MAX_DIGEST_STORIES, 15)
        self.assertEqual(len(result["stories"]), MAX_DIGEST_STORIES)


if __name__ == "__main__":
    unittest.main()
