from setuptools import setup

setup(
    name="cursor-pr-review",
    version="1.0.0",
    description="Production-ready AI-powered PR review tool",
    python_requires=">=3.8",
    install_requires=[
        "requests>=2.28.0",
        "pyyaml>=6.0",
    ],
    py_modules=["cursor_pr_review"],
    entry_points={
        "console_scripts": [
            "cursor-pr-review=cursor_pr_review:main",
        ],
    },
)
