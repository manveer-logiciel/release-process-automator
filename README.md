# Release Process Automator

A comprehensive solution for automating JIRA card creation with both CLI and web interfaces, featuring OAuth authentication for JIRA and GitHub.

## 🚀 Features

### CLI Application
- **Multi-project support** - Choose from available projects on your board
- **Production Change defaults** - Optimized for release workflows
- **Interactive prompts** - Due date and project selection
- **Dry-run mode** - Preview cards before creation
- **OAuth authentication** - Secure JIRA and GitHub integration

### Web Application
- **Modern UI** - Beautiful, responsive web interface
- **OAuth flows** - Secure authentication with JIRA and GitHub
- **Real-time validation** - Dynamic form validation and feedback
- **Multi-project support** - Automatic project and issue type detection

## 🛠️ Setup

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Environment Configuration
Copy `.env.example` to `.env` and configure your OAuth applications:

```bash
cp .env.example .env
```

Required OAuth applications:
- **JIRA OAuth App** - Create at https://developer.atlassian.com/console/myapps/
- **GitHub OAuth App** - Create at https://github.com/settings/applications/new
- **Slack App** (optional) - Create at https://api.slack.com/apps

### 3. OAuth Setup

#### JIRA OAuth App
1. Go to https://developer.atlassian.com/console/myapps/
2. Create new app → OAuth 2.0 (3LO)
3. Set redirect URI: `http://localhost:3000/auth/jira/callback`
4. Add scopes: `read:jira-work`, `write:jira-work`, `manage:jira-project`

#### GitHub OAuth App
1. Go to https://github.com/settings/applications/new
2. Set Authorization callback URL: `http://localhost:3000/auth/github/callback`
3. Copy Client ID and Client Secret

## 🖥️ Usage

### CLI Application
```bash
# Interactive project selection
python jira_cli.py create -t "Deploy new feature" -d "Production deployment"

# Specify project directly
python jira_cli.py create -t "Deploy feature" -d "Description" --project DEVOPS

# With due date
python jira_cli.py create -t "Deploy feature" -d "Description" --due-date "2025-08-30"

# List available projects
python jira_cli.py projects

# Check connection and project info
python jira_cli.py info --project DEVOPS
```

### Web Application
```bash
# Start the web server
python slack_app.py
```

Then visit http://localhost:3000 to:
1. Authenticate with JIRA and GitHub
2. Create JIRA cards through the web interface
3. View authentication status and manage connections

## 📋 CLI Options

### Create Command
- `--title, -t`: Card title/summary (required)
- `--description, -d`: Card description (required)
- `--project, -P`: Project key (interactive selection if not provided)
- `--type, -T`: Issue type (default: Production Change)
- `--priority, -p`: Priority level (Highest, High, Medium, Low, Lowest)
- `--work-type, -w`: Work type (default: Production Change)
- `--due-date`: Due date in YYYY-MM-DD format (prompted if not provided)
- `--dry-run`: Preview without creating

### Other Commands
- `projects`: List all available projects
- `info`: Show connection status and configuration
- `info --project KEY`: Show specific project details

## 🌐 Web Interface Features

### Authentication Dashboard
- Visual status indicators for JIRA and GitHub
- One-click OAuth authentication
- Secure session management

### Card Creation Form
- Dynamic project selection
- Auto-loading issue types per project
- Date picker with smart defaults
- Real-time validation and feedback
- Success/error messaging with direct links

### Security Features
- OAuth 2.0 with PKCE
- Secure session storage
- Token refresh handling
- CSRF protection

## 🔧 API Endpoints

- `GET /` - Authentication dashboard
- `GET /auth/jira` - Initiate JIRA OAuth
- `GET /auth/github` - Initiate GitHub OAuth
- `GET /create-card` - Card creation form
- `POST /api/create-issue` - Create JIRA issue
- `GET /api/projects/{key}/issue-types` - Get issue types
- `GET /logout` - Clear authentication

## 📁 Project Structure

```
release-card-automator-2/
├── jira_cli.py              # CLI application
├── slack_app.py             # Web application
├── templates/               # HTML templates
│   ├── index.html          # Authentication dashboard
│   └── create_card.html    # Card creation form
├── requirements.txt         # Python dependencies
├── .env.example            # Environment template
├── .gitignore             # Git ignore rules
└── README.md              # This file
```

## 🚀 Deployment

### Local Development
```bash
python slack_app.py
# Access at http://localhost:3000
```

### Production Deployment
1. Update redirect URIs in OAuth apps to production URLs
2. Set production environment variables
3. Use a production WSGI server like Gunicorn
4. Configure HTTPS for OAuth security

## 🔍 Troubleshooting

### CLI Issues
- Run `python jira_cli.py info` to check connection
- Use `--dry-run` to test without creating cards
- Check project availability with `python jira_cli.py projects`

### Web App Issues
- Verify OAuth app configurations and redirect URIs
- Check browser console for JavaScript errors
- Ensure all environment variables are set correctly

### Authentication Issues
- Verify OAuth client IDs and secrets
- Check redirect URI matches exactly
- Ensure proper scopes are configured

## 📝 License

This project is licensed under the MIT License.
