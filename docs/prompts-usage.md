# Using Custom Prompts in Cursor PR Review

## Manual Review with Custom Prompts

### Using Built-in Prompts

```bash
# Use the default prompt
python cursor_pr_review.py review-pr owner/repo 123

# Use a specific built-in prompt
python cursor_pr_review.py review-pr owner/repo 123 --prompt strict
python cursor_pr_review.py review-pr owner/repo 123 --prompt lenient
python cursor_pr_review.py review-pr owner/repo 123 --prompt security-focused
```

### Using the Brutal Prompt

```bash
# Use the brutal prompt for harsh, honest reviews
python cursor_pr_review.py review-pr owner/repo 123 --prompt brutal
```

### Using Custom Prompts by ID

```bash
# First, list available prompts
python cursor_pr_review.py prompt list

# Use a prompt by its ID
python cursor_pr_review.py review-pr owner/repo 123 --prompt-id custom_f38746d4
```

## Automated Reviews with Custom Prompts

### Environment Variables for GitHub Actions

You can configure automated reviews using environment variables:

- `REVIEW_PROMPT_TYPE`: Set the prompt type (default, strict, lenient, security-focused, brutal)
- `REVIEW_PROMPT_TEMPLATE`: Provide a complete custom prompt template
- `REVIEW_STRICTNESS`: Set review strictness (lenient, balanced, strict)
- `AUTO_REQUEST_CHANGES`: Whether to auto-request changes for critical issues (true/false)
- `CODERABBIT_THRESHOLD`: CodeRabbit integration threshold (low, medium, high)

### Example: Using Brutal Prompt in GitHub Actions

1. **Set the prompt type in your repository secrets or workflow:**

```yaml
name: AI PR Review
on:
  pull_request:
    types: [opened, synchronize, reopened]

jobs:
  ai-review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      - run: pip install requests pyyaml
      - name: Run AI Review
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
          REVIEW_PROMPT_TYPE: brutal  # Use brutal prompt
          REVIEW_STRICTNESS: strict   # Be extra strict
          AUTO_REQUEST_CHANGES: true  # Auto-request changes
        run: python cursor_pr_review.py review-pr ${{ github.repository }} ${{ github.event.pull_request.number }}
```

2. **Or use a fully custom prompt template:**

```yaml
- name: Run AI Review
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
    OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
    REVIEW_PROMPT_TEMPLATE: |
      You are a senior code reviewer focused on security.
      Review this code for security vulnerabilities only.
      Be direct and actionable in your feedback.
```

### Setting Different Prompts for Different Branches

```yaml
- name: Run AI Review
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
    OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
    # Use brutal prompt for main branch, lenient for others
    REVIEW_PROMPT_TYPE: ${{ github.base_ref == 'main' && 'brutal' || 'lenient' }}
```

## Managing Prompts

### Create a New Prompt

```bash
# Interactive prompt creation
python cursor_pr_review.py prompt create
```

### Set Default Prompts

```bash
# Set brutal as default for all code reviews
python cursor_pr_review.py prompt set-default code_review all brutal

# Set different defaults for different languages
python cursor_pr_review.py prompt set-default code_review python strict
python cursor_pr_review.py prompt set-default code_review javascript lenient
```

### View and Edit Prompts

```bash
# View a prompt
python cursor_pr_review.py prompt view brutal

# Edit a custom prompt
python cursor_pr_review.py prompt edit custom_f38746d4

# View prompt history
python cursor_pr_review.py prompt history custom_f38746d4
```

## Best Practices

1. **Development vs Production**: Use lenient prompts for development branches and strict/brutal prompts for production branches
2. **Security-Critical Code**: Always use security-focused or brutal prompts for authentication, encryption, or payment code
3. **Team Preferences**: Different teams might prefer different review styles - configure per repository
4. **Gradual Adoption**: Start with balanced prompts and gradually increase strictness as the team adapts

## Example Prompt Types

- **default**: Balanced review focusing on security, bugs, performance, and quality
- **strict**: Zero tolerance for any issues, very detailed analysis
- **lenient**: Focus only on critical issues, more constructive tone
- **security-focused**: Comprehensive security analysis with OWASP mapping
- **brutal**: Harsh, honest feedback with no sugar-coating (see `docs/brutalprompt.md`)

## Troubleshooting

If a prompt isn't loading:
1. Check that the prompt file exists in `~/.cursor-pr-review/prompts/`
2. For brutal prompt, ensure `docs/brutalprompt.md` exists
3. Use `python cursor_pr_review.py prompt list` to see available prompts
4. Check workflow logs for any error messages about prompt loading