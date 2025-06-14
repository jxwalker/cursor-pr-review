# Cursor PR Review

**Simple AI Code Reviewer for Vibe Coders**

---

## 🚀 Overview

**Cursor PR Review** is a dead simple AI code reviewer that actually works. After being refactored twice to remove complexity, this tool now does one thing well: review your PRs and post clear, actionable feedback.

- **Simple:** ~400 lines of code that just works
- **Clear output:** No garbage, no "Unknown location", no empty fixes
- **Multiple review styles:** Default, brutal, lenient, or security-focused
- **Works with:** OpenAI GPT-4 or Anthropic Claude

---

## ⚠️ SIMPLICITY WARNING

This code has been refactored TWICE to remove complexity. Please DO NOT add:
- Complex parsing systems
- Multiple abstraction layers  
- Issue deduplication
- Enhanced analyzers
- Complicated formatters

Keep it simple. It works.

---

## ✨ Features

- **Automated PR Review:** Get AI feedback on every PR
- **Clear feedback:** Specific file, line number, issue, and fix
- **Multiple prompts:** Choose your review style
- **No complexity:** Just works

---

## 🛠️ Quick Start

### 1. Install Requirements

```bash
pip install requests
```

That's it. No complex dependencies.

### 2. Setup

```bash
python cursor_pr_review.py setup
```

Enter your:
- GitHub token (from https://github.com/settings/tokens)
- OpenAI or Anthropic API key

### 3. Review a PR

```bash
# Default review
python cursor_pr_review.py review-pr owner/repo 123

# Brutal review
python cursor_pr_review.py review-pr owner/repo 123 --prompt brutal

# Lenient review  
python cursor_pr_review.py review-pr owner/repo 123 --prompt lenient

# Security-focused
python cursor_pr_review.py review-pr owner/repo 123 --prompt security
```

Push the generated workflow file to your repo. Every new PR will now be automatically reviewed!

### 4. Manual Review (Optional)

```bash
python cursor_pr_review_final.py review-pr owner/repo 123
```

---

## 🧪 Testing

Run the full test suite:

```bash
python test_final.py
```

Or test specific components:

```bash
python -m pytest test_final.py::TestReviewConfig -v
```

---

## 📝 Why Use Cursor PR Review?

- **Save Time:** Let AI handle the repetitive parts of code review.
- **Improve Quality:** Catch security, style, and logic issues before merging.
- **Stay Modern:** Built with best practices, modern Python, and robust workflows.
- **For Vibe Coders:** Designed for teams who want to move fast and keep their codebase fresh.

---

## 🤝 Contributing

We welcome contributions from the community! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

- Open issues for bugs or feature requests.
- Submit pull requests for improvements or fixes.
- Join the discussion and help shape the future of automated code review.

---

## 📄 License

MIT License. See [LICENSE](LICENSE) for details.

---

## 🙏 Acknowledgements

- Powered by OpenAI, Anthropic, and CodeRabbit.
- Inspired by the need for better, faster, and more reliable code reviews.

---

**Ready to automate your PR feedback?**  
Clone, set up, and let the vibes (and the bots) handle your code reviews!

---

Code review, feedback, and suggestions are always welcome!