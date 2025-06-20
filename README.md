# combat-sca

This repository demonstrates a simple approach for monitoring GitHub Actions for potential supply chain attacks. It includes:

- `DETECTION_SYSTEM_DESIGN.md` – a high-level design for detecting compromised GitHub Actions.
- `monitor_action.py` – a minimal script that downloads an Action repository archive, computes file checksums, and looks for suspicious patterns such as secret exposure commands and unexpected network endpoints.

## Usage

1. Obtain a GitHub Personal Access Token and a Slack webhook URL (optional).
2. Create a `.env` file in the project root (see `.env.example`):

```env
GITHUB_TOKEN=your_github_token_here
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/your/webhook/url
```

Alternatively, you can export these as environment variables or pass them as command-line arguments.

3. Run the monitor with an Action repository in `owner/repo` format:

```bash
python monitor_action.py tj-actions/changed-files
```

To send Slack notifications on suspicious findings, ensure `SLACK_WEBHOOK_URL` is set in your `.env` or environment variables, or provide it via `--slack-webhook`:

```bash
python monitor_action.py tj-actions/changed-files --slack-webhook https://hooks.slack.com/services/your/webhook/url
```

The script posts a message whenever it finds suspicious patterns or external
domains.

On the first run, a baseline file is created in the `baselines` directory. On subsequent runs, the script checks for changes and prints any suspicious patterns detected, including external domains referenced by the action.

> **Note**: This is only a proof of concept and does not replace a full monitoring system.

## .env Example

See `.env.example` for the required variables:

```env
GITHUB_TOKEN=your_github_token_here
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/your/webhook/url
```

## Hosting and Scheduling

Run the monitor on a cloud VM or container and schedule it with cron to check
actions regularly:

```cron
0 * * * * /usr/bin/python /path/to/monitor_action.py owner/repo --baseline /var/monitor/baseline.json >> /var/log/action_monitor.log 2>&1
```

You can also containerize the script and run it on AWS Lambda, Google Cloud Run,
or another serverless platform. Use the provider's scheduler to trigger the
monitor periodically and configure the Slack webhook so alerts reach your
security team.

