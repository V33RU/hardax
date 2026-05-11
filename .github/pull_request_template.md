## Summary

<!-- What does this PR change and why? -->

## Type of change

- [ ] Bug fix
- [ ] New feature / flag
- [ ] New security check (added to `commands/*.json`)
- [ ] Documentation
- [ ] Refactor / cleanup

## Target branch

- [ ] This PR targets `dev` (not `main`)

## Verification

<!-- How did you test this? Paste relevant output / a successful run. -->

```
python3 hardax.py --version
# ...
```

## Checklist

- [ ] Code parses (`python3 -c "import ast; ast.parse(open('hardax.py').read())"`)
- [ ] New JSON checks have a valid `safe_pattern` regex
- [ ] No new required dependencies added without discussion
- [ ] README / docs updated if user-facing behavior changed
