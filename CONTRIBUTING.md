# Contributing to Fraud Guard Plugin for Kong

Thank you for your interest in contributing to this project! Please read the following guidelines before submitting your contributions.

## Branch Protection Strategy

This repository follows a structured branch protection model:

### `main` Branch (Protected)
- **Direct pushes are not allowed.** All changes must go through pull requests.
- This is the production branch that triggers the CI/CD pipeline and builds the Docker image.
- Pull requests targeting `main` require passing CI checks before merging.

### `dev` Branch (Protected)
- **Only the repository owner (@recepbaykara) can push directly** to this branch.
- Pull requests targeting `dev` can only be approved by @recepbaykara.
- This branch is used for development and integration testing.

### Other Branches
- Open for public contributions.
- Contributors are encouraged to create feature branches from `dev` for their work.

## How to Contribute

1. **Fork the repository** and create your feature branch from `dev`:
   ```bash
   git checkout dev
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes** and ensure they follow the project conventions.

3. **Test your changes** locally:
   ```bash
   # Validate Lua syntax
   find . -name "*.lua" -type f -exec lua5.1 -c {} \;
   ```

4. **Submit a pull request** targeting the `dev` branch.

5. Once approved and merged into `dev`, changes will be promoted to `main` via a separate pull request.

## Pull Request Guidelines

- Provide a clear description of what your changes do.
- Reference any related issues.
- Ensure all CI checks pass before requesting a review.
- Keep pull requests focused and avoid unrelated changes.
