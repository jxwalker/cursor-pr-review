# Setting Up Automated PR Reviews

GitHub Actions has limitations with the default `GITHUB_TOKEN`. To enable automated PR reviews that can post comments, you need to create a Personal Access Token (PAT).

## Steps

1. **Create a Personal Access Token**
   - Go to https://github.com/settings/tokens/new
   - Name: `PR_REVIEW_TOKEN`
   - Expiration: 90 days (or your preference)
   - Scopes needed:
     - `repo` (Full control of private repositories)
     - `write:discussion` (Write access to discussions)

2. **Add Token to Repository Secrets**
   - Go to your repo → Settings → Secrets and variables → Actions
   - Click "New repository secret"
   - Name: `PR_REVIEW_TOKEN`
   - Value: Your PAT from step 1

3. **Add OpenAI API Key**
   - Click "New repository secret" again
   - Name: `OPENAI_API_KEY`
   - Value: Your OpenAI API key

4. **Push the Workflow**
   - The `.github/workflows/ai-review.yml` is already configured
   - It will use `PR_REVIEW_TOKEN` if available, otherwise fall back to `GITHUB_TOKEN`

## How It Works

When a PR is opened or updated:
1. GitHub Actions triggers the workflow
2. The simple reviewer analyzes the diff
3. Posts review comments directly on the PR
4. Each issue shows: file, line number, description, and fix

## Customization

Edit the workflow to change the review style:
```yaml
env:
  REVIEW_PROMPT_TYPE: brutal  # Options: default, brutal, lenient, security
```

## Troubleshooting

If reviews aren't posting:
- Check Actions tab for workflow runs
- Ensure `PR_REVIEW_TOKEN` secret is set correctly
- Verify the token has the right permissions
- Check workflow logs for errors