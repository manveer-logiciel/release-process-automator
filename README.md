# JIRA CLI Application

A command-line interface for creating JIRA cards using title and description inputs.

## Setup

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Environment Configuration:**
   Ensure your `.env` file contains the required JIRA credentials:
   ```
   JIRA_TOKEN=your_jira_api_token
   JIRA_BASE_URL=https://your-domain.atlassian.net
   JIRA_EMAIL=your-email@domain.com
   JIRA_BOARD=https://your-domain.atlassian.net/jira/software/c/projects/PROJECT/boards/123
   ```

## Usage

### Create a JIRA Card
```bash
python jira_cli.py create -t "Card Title" -d "Card Description"
```

### Advanced Options
```bash
python jira_cli.py create \
  --title "Fix login bug" \
  --description "Users cannot login with special characters in password" \
  --type "Bug" \
  --priority "High"
```

### Available Options
- `--title, -t`: Card title/summary (required)
- `--description, -d`: Card description (required)
- `--type, -T`: Issue type (default: Task)
- `--priority, -p`: Priority level (Highest, High, Medium, Low, Lowest)
- `--dry-run`: Preview what would be created without actually creating it

### Check Connection
```bash
python jira_cli.py info
```

### Help
```bash
python jira_cli.py --help
python jira_cli.py create --help
```

## Examples

**Basic card creation:**
```bash
python jira_cli.py create -t "Update documentation" -d "Add API examples to README"
```

**High priority bug:**
```bash
python jira_cli.py create -t "Critical login issue" -d "Users cannot authenticate" --type "Bug" --priority "High"
```

**Dry run to preview:**
```bash
python jira_cli.py create -t "Test card" -d "Testing description" --dry-run
```

## Features

- ✅ Create JIRA cards with title and description
- ✅ Support for different issue types and priorities
- ✅ Connection validation
- ✅ Dry-run mode for testing
- ✅ Automatic project detection from board URL
- ✅ Comprehensive error handling

## Troubleshooting

**Connection Issues:**
- Verify your JIRA token is valid and has appropriate permissions
- Check that the base URL is correct
- Ensure your email matches the JIRA account

**Permission Errors:**
- Make sure your JIRA token has permission to create issues in the target project
- Verify the project key is correct

**Issue Type Errors:**
- Run `python jira_cli.py info` to see available issue types for your project
