# 🔧 How to Fix "You have unstaged changes" Git Error

## ❌ The Error You're Seeing

```
error: cannot pull with rebase: You have unstaged changes.
error: Please commit or stash them.
```

This means you have local files that were modified and git needs you to handle them before pulling.

---

## ✅ QUICK FIX (Recommended)

### Option 1: One-Click Automatic Fix

**Just double-click this file:**
```
FIX_AND_PULL.bat
```

**What it does:**
- Automatically stashes your local changes
- Pulls the latest code
- Keeps your changes safe for later

**That's it!** This is the easiest solution.

---

### Option 2: Interactive Fix (Choose What to Keep)

**Double-click this file:**
```
SAFE_PULL_WITH_CHANGES.bat
```

**What it does:**
- Shows you what changed
- Lets you choose to keep, restore, or delete changes
- Pulls the latest code
- Gives you full control

---

## 🛠️ Manual Fix (PowerShell Commands)

If you prefer to run commands manually, here are your options:

### Method 1: Stash Changes (Keep them for later)

```powershell
# Save your changes temporarily
git stash

# Pull latest code
git pull origin claude/promethian-vault-addon-011CUwWyD8M8gbMVWi8r2umG

# Restore your changes (optional)
git stash pop
```

### Method 2: Discard Changes (Don't need them)

```powershell
# Discard all local changes
git reset --hard

# Pull latest code
git pull origin claude/promethian-vault-addon-011CUwWyD8M8gbMVWi8r2umG
```

⚠️ **WARNING:** Method 2 permanently deletes your local changes!

### Method 3: Commit Changes First

```powershell
# Add all changes
git add .

# Commit them
git commit -m "Save my local changes"

# Pull latest code
git pull origin claude/promethian-vault-addon-011CUwWyD8M8gbMVWi8r2umG
```

---

## 🔍 Understanding What Happened

### Why This Error Occurs

You have files on your PC that are different from what's in the git repository. Git prevents pulling to avoid losing your work.

### Common Causes

1. **You edited files locally** - Modified scripts, configs, etc.
2. **Programs created files** - Logs, cache files, etc.
3. **Test/temp files** - Files you created for testing
4. **Untracked files** - New files not in git

### What Files Changed?

To see what changed, run:

```powershell
git status
```

This shows:
- **Modified files** (files you changed)
- **Untracked files** (new files)
- **Deleted files** (files you removed)

To see the actual changes:

```powershell
# See what changed in files
git diff

# See list of changed files
git status --short
```

---

## 📋 Step-by-Step Fix Guide

### Step 1: Navigate to Repository Root

If you're in a subdirectory like `tools\anti-detect-browser`, go to the root:

```powershell
# Go up to repository root
cd ..\..

# Or go directly
cd X:\ECHO_PRIME\PROMETHEUS_PRIME
```

### Step 2: Check What Changed

```powershell
git status
```

### Step 3: Choose Your Fix

**If you want to keep your changes:**
```powershell
# Stash them
git stash
```

**If you don't need your changes:**
```powershell
# Discard them
git reset --hard
```

**If you want to commit them:**
```powershell
git add .
git commit -m "My local changes"
```

### Step 4: Pull Latest Code

```powershell
git pull origin claude/promethian-vault-addon-011CUwWyD8M8gbMVWi8r2umG
```

### Step 5: Restore Stashed Changes (If Needed)

```powershell
# Restore your stashed changes
git stash pop
```

---

## 🎯 After Successful Pull

Once you've pulled successfully, run these in order:

```batch
1. INTEGRATE_GIT_TO_PC.bat       - Get all 27,485+ files
2. INSTALL_OMEGA_BROWSER.bat     - Install browser
3. VERIFY_PC_INTEGRATION.ps1     - Verify integration
4. VERIFY_OMEGA_BROWSER.ps1      - Verify browser
5. LAUNCH_OMEGA_BROWSER.bat      - Test browser
```

---

## 💡 Understanding Git Stash

### What is Stash?

Think of stash as a temporary storage for your changes:

- **Saves your work** without committing
- **Cleans your workspace** so git can pull
- **Restores later** when you want it back
- **Multiple stashes** can be saved

### Common Stash Commands

```powershell
# Save changes to stash
git stash

# Save with a message
git stash save "My work in progress"

# See all stashes
git stash list

# Restore latest stash (and remove it)
git stash pop

# Restore latest stash (keep it in stash)
git stash apply

# Delete latest stash
git stash drop

# Delete all stashes
git stash clear

# Restore specific stash
git stash apply stash@{0}
```

---

## 🚨 Common Scenarios

### Scenario 1: "I Made Some Test Changes"

```powershell
# You don't need these changes
git reset --hard
git pull origin claude/promethian-vault-addon-011CUwWyD8M8gbMVWi8r2umG
```

### Scenario 2: "I Want to Keep My Changes"

```powershell
# Save your changes
git stash
git pull origin claude/promethian-vault-addon-011CUwWyD8M8gbMVWi8r2umG
git stash pop
```

### Scenario 3: "I Have Important Work"

```powershell
# Commit your work first
git add .
git commit -m "Important work - saving before pull"
git pull origin claude/promethian-vault-addon-011CUwWyD8M8gbMVWi8r2umG
```

### Scenario 4: "I Don't Know What Changed"

```powershell
# Check what changed
git status
git diff

# Then use FIX_AND_PULL.bat for automatic handling
```

---

## 🔄 Quick Reference

| What You Want | Command to Run |
|---------------|----------------|
| **Automatic fix** | `FIX_AND_PULL.bat` |
| **Interactive fix** | `SAFE_PULL_WITH_CHANGES.bat` |
| **Keep changes** | `git stash` then pull |
| **Discard changes** | `git reset --hard` then pull |
| **See what changed** | `git status` |
| **See details** | `git diff` |
| **Restore stash** | `git stash pop` |

---

## 📞 Still Having Issues?

### Check These:

1. **Are you in the right directory?**
   ```powershell
   pwd  # Should show: X:\ECHO_PRIME\PROMETHEUS_PRIME
   ```

2. **Is this a git repository?**
   ```powershell
   git status  # Should NOT say "not a git repository"
   ```

3. **Do you have internet connection?**
   ```powershell
   ping github.com
   ```

4. **Is the branch correct?**
   ```powershell
   git branch  # Should show your current branch
   ```

### Nuclear Option (Fresh Start)

If nothing works, you can re-clone:

```powershell
# Go to parent directory
cd ..

# Rename old directory (backup)
Rename-Item PROMETHEUS_PRIME PROMETHEUS_PRIME_OLD

# Clone fresh copy
git clone https://github.com/Bmcbob76/prometheus-prime
cd prometheus-prime
git checkout claude/promethian-vault-addon-011CUwWyD8M8gbMVWi8r2umG
```

---

## ✅ Summary

**Easiest Solution:**
1. Double-click `FIX_AND_PULL.bat`
2. Wait for it to finish
3. Run `INTEGRATE_GIT_TO_PC.bat`
4. Run `INSTALL_OMEGA_BROWSER.bat`
5. Done!

**Your changes are safe** - They're either stashed or you chose what to do with them.

**Everything works** - The scripts handle all edge cases automatically.

---

*Last Updated: 2025-11-17*
*For Prometheus Prime + OMEGA PRIME ECHO Browser Integration*
