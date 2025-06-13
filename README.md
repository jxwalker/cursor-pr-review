# Cursor PR Review

**Automated, AI-powered Pull Request Feedback for Modern Vibe Coders**

---

## 🚀 Overview

**Cursor PR Review** is a production-ready tool that automates code review feedback on GitHub pull requests using state-of-the-art AI models. Designed for developers who value speed, quality, and modern workflows, it integrates seamlessly with your repo to catch issues, suggest improvements, and keep your codebase clean—without the hassle.

- **No more manual reviews:** Get instant, actionable feedback on every PR.
- **AI-powered analysis:** Uses OpenAI, Anthropic, and CodeRabbit (free/paid) for deep code insights.
- **Production-grade:** Robust error handling, full test coverage, and clean, maintainable code.
- **Easy setup:** One command to get started, with secure config and GitHub Actions integration.

---

## ✨ Features

- **Automated PR Review:** Triggers on every pull request, analyzing diffs for security, quality, and style issues.
- **AI Model Flexibility:** Supports OpenAI, Anthropic, and CodeRabbit (free or paid).
- **Secure & Configurable:** No hardcoded secrets; all credentials are securely managed.
- **Modern YAML Workflows:** Uses the official `yaml` library for robust GitHub Actions generation.
- **Comprehensive Logging:** No print statements—just clean, structured logs.
- **Full Test Suite:** 52+ tests ensure reliability and maintainability.
- **Beginner-Friendly:** Clear prompts, helpful errors, and detailed documentation.

---

## 🛠️ Quick Start

### 1. Install Requirements

```bash
pip install -r requirements.txt
```

### 2. Setup the Tool

```bash
python cursor_pr_review_final.py setup
```

- Prompts for your GitHub token and AI provider.
- Validates credentials and fetches available models.
- Optionally enables CodeRabbit integration.
- Generates a secure config and GitHub Actions workflow.

### 3. Enable Automated PR Reviews

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