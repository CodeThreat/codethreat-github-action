# Contributing to CodeThreat GitHub Action

First off, thank you for considering contributing to CodeThreat GitHub Action! It's people like you that make CodeThreat such a great tool.

## Code of Conduct

This project and everyone participating in it is governed by the [Contributor Covenant](https://www.contributor-covenant.org/). By participating, you are expected to uphold this code.

## Development Process

1. Fork the repository
2. Create your feature branch from `develop`
   ```bash
   git checkout -b feature/amazing-feature
   ```
3. Make your changes
4. Run tests and ensure CI passes
5. Update documentation as needed
6. Commit your changes
   ```bash
   git commit -m 'feat: add amazing feature'
   ```
7. Push to your fork
   ```bash
   git push origin feature/amazing-feature
   ```
8. Open a Pull Request

## Branch Naming Convention

- `feature/*`: New features or enhancements
- `bugfix/*`: Bug fixes
- `hotfix/*`: Critical fixes for production
- `docs/*`: Documentation updates
- `test/*`: Test-related changes
- `refactor/*`: Code refactoring
- `chore/*`: Routine tasks, maintenance, etc.

## Commit Message Format

We follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

```
type(scope): description

[optional body]

[optional footer]
```

### Types
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation only changes
- `style`: Changes that do not affect the meaning of the code
- `refactor`: Code change that neither fixes a bug nor adds a feature
- `test`: Adding missing tests or correcting existing tests
- `chore`: Changes to the build process or auxiliary tools

### Examples

```bash
feat(scanner): add support for custom policy files
fix(auth): resolve token validation issue
docs(readme): update installation instructions
```

## Testing Requirements

- Unit tests required for all new features
- Minimum 80% code coverage
- Integration tests for API endpoints
- End-to-end tests for critical paths

### Running Tests

```bash
# Install dependencies
npm install

# Run unit tests
npm test

# Run tests with coverage
npm run test:coverage
```

## Code Style

- Follow existing code style
- Document public APIs using JSDoc
- Keep functions small and focused
- Use meaningful variable names
- Add comments for complex logic

## Pull Request Process

1. Update documentation for any new features or changes
2. Add or update tests as needed
3. Ensure all CI checks pass
4. Get review from at least one maintainer
5. Squash commits before merge

## Release Process

1. Merge changes into `develop`
2. Create a release branch when ready
   ```bash
   git checkout -b release/v1.2.3
   ```
3. Update version numbers
4. Create pull request to `main`
5. After merge, tag the release
   ```bash
   git tag -a v1.2.3 -m "Release v1.2.3"
   ```

## Questions or Problems?

- Check existing issues
- Open a new issue with a clear description
- Tag issues appropriately
- Provide reproduction steps for bugs

## Additional Resources

- [CodeThreat Documentation](https://docs.codethreat.com)
- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [Conventional Commits](https://www.conventionalcommits.org/)
- [Contributor Covenant](https://www.contributor-covenant.org/)

## License

By contributing, you agree that your contributions will be licensed under the same license as the project. 