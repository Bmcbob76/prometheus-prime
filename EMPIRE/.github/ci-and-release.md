# CI Processes

## Pull Requests - Build and Test
All pull requests will run the `Lint and Test` workflow.

* The workflow will run `black` and `isort` checks and then run `pytest` on Python 3.8, 3.9, and 3.10.
* If the pull request is coming from a `release/*` branch, it will build the docker image and run `pytest` on it
* If the pull request changes the `install.sh` script, it will run the install script on the supported OS and check for errors

When submitting a pull request to `private-main`, the label `auto-merge-downstream` can be added. If the label is present, then merging a branch to `private-main` will automatically trigger the prerelease step of merging `private-main` into `sponsors-main` and `kali-main`.

## BC-SECURITY/Empire-Sponsors Sponsors & Kali Release Process
*Note: Starting in 2023, the Kali team will be pulling from the public repo.
I am keeping the Kali workflows running for now with the exception of the tagging.
This is mostly out of laziness since I just wrote all of the CI/CD. In the near future,
we can rework these jobs to be more like "sponsors & other downstream" releases.*

Sponsors and Kali releases go through the same release process. It is easier to manage Empire releases by not allowing them to be released at different times and have the version numbers diverge.
A side effect of this is its possible for a version bump to be empty (no changes) and still be released.

### 1. cherry-pick any changes from BC-SECURITY/Empire#main to BC-SECURITY/Empire-Sponsors#private-main

Pull requests that should be merged from `main` to `private-main` can be auto-cherry-picked using the `Prerelease - Cherry Pick Main` workflow.
Add the label `auto-cherry-pick` to the pull request and upon merge, it will open a pull request into `BC-SECURITY/Empire-Sponsors#private-main`, assuming no conflicts.
If there are conflicts, you must cherry-pick the commits manually. See the steps below.

If you forgot to add the label, the workflow can be manually run, just enter the commit hash as an input to the workflow.

If you don't feel comfortable pushing to `private-main`, you can branch from `private-main` before cherry-picking and open a pull request to merge into `private-main`.

```bash
cd /tmp
git clone --recursive git@github.com:bc-security/empire-sponsors.git
cd empire-sponsors
git remote add upstream git@github.com:bc-security/empire.git
git fetch upstream
git checkout private-main

# cherry-pick all commits needed from main to private-main
git cherry-pick <commit-hash>

# If there's any conflicts, resolve them then:
git add -A
git cherry-pick --continue

# push
git push origin private-main
```

**Potential Enhancement:** Could add a GitHub workflow that you supply a commit hash and it will cherry-pick it into `private-main` and open a pull request.

### 2. Merge Empire-Sponsors/private-main -> (Empire-Sponsors/sponsors-main, Empire-Sponsors/kali-main)
Run the `Prerelease - Merge private-main` manual workflow. The branch that it runs on doesn't matter.
The workflow will merge `private-main` into `sponsors-main` and `kali-main`.

No pull requests will be opened, if there are issues that broke the code, they will manifest in CI when the release PR is open.

If this step fails, it is probably due to a merge conflict. In this case,
the merge conflicts need to be resolved, and its best to run this locally.

<details>
<summary>If `private-main` -> `kali-main` fails</summary>
<p>

```bash
cd /tmp
git clone --recursive git@github.com:bc-security/empire-sponsors.git
cd empire-sponsors
git checkout kali-main
git merge origin/private-main

# Fix the conflicts, then:
git add -A
git merge --continue
git push origin kali-main
```
</p>
</details>

<details>
<summary>If `private-main` -> `sponsors-main` fails</summary>
<p>

```bash
cd /tmp
git clone --recursive git@github.com:bc-security/empire-sponsors.git
cd empire-sponsors
git checkout sponsors-main
git merge origin/private-main

# Fix the conflicts, then:
git add -A
git merge --continue
git push origin sponsors-main
```
</p>
</details>

**Potential Enhancement:** I'm still considering if this step should open PRs instead of doing direct merges.

### 3. Start Private Release
Start a release by running the `Private - Create Release` manual workflow.
The branch that it runs on doesn't matter.
The workflow will then create a release branch, push it to the repo, and create a pull request into `private-main`.

* Updates `pyproject.toml` version
* Updates `empire.py` version
* Updates `CHANGELOG.md`

### 4. Manual Step - Merge private-main release PR
Once the first workflow runs, it will open one pull request from the `release/v{version}-private` branch to `private-main`.

Check the changelog on this branch, this will be the changelog that is used for the release notes.

You can get a list of the new commits that are in this release by using the following command. Replace `v4.9.0-private` with whatever the previous release was.
```
git --no-pager log --no-merges --pretty='format:%cs %s' private-main...v4.9.0-private
```

Merge the pull request. **DO NOT SQUASH**

**Note**: If at this point there are additional changes for the release, merge them into the release branch, not
the `private-main` branch.

**Potential Enhancement:** Use a git diff to generate a list of changes as suggestions for the release notes.

### 5. Private - Tag and Release
Once the `release/` pull request is merged, the `Private - Tag Release` workflow will automatically run.
The workflow will create a tag and release on the `HEAD` of `private-main` using the release notes from `CHANGELOG.md` for the body of the release.

### 6. Repeat Step 2 - Prerelease Merge
Repeat step 2 to merge `private-main` into `sponsors-main` and `kali-main`.

### 7. Start Sponsor/Kali Release
Start the release by running the `Sponsors & Kali - Create Release` manual workflow.
If starkiller needs to be updated, provide a `starkillerVersion` input. The value provided should be a git tag minus the `-kali` or `-sponsors` suffix.

If a Starkiller tag was provided, it will update the Starkiller config and the changelog accordingly.

A release PR will then be opened for each branch and the test suite will run.


#### 8. Manual Step - Merge sponsor/kali release PRs
Once the workflow runs, it will open two pull requests from the `release/v{version}-sponsors` and `release/v{version}-kali` branches to `sponsors-main` and `kali-main` respectively.

Check the changelog on these branches, this will be the changelog that is used for the release notes.

If there are sponsor specific changelog entries that need to be added, add them to the `CHANGELOG-SPONSORS.md` file on the release branch.

You can get a list of the new commits that are in this release by using the following command. Replace `v4.9.0-sponsors` with whatever the previous release was.
```
git --no-pager log --no-merges --pretty='format:%cs %s' sponsors-main...v4.9.0-sponsors
```

Merge the pull requests. **DO NOT SQUASH**

**Note**: If at this point there are additional changes for the release, merge them into the release branch, not
the `sponsors-main` branch or `kali-main` branch.

**Potential Enhancement** We could add automation that copies the `unreleased` section from the target branch to the version section in the `head` branch.

### 9. Tag and Release
Once the pull requests are merged, the `Sponsors - Tag Release` and `Kali - Tag Release` workflows will automatically run.
The workflows will create a tag and release on the `HEAD` of `sponsors-main` and `kali-main`, using the release notes from `CHANGELOG.md` for the body of the release.

### Setup
Requires a secret in the repo `RELEASE_TOKEN` that has `repo` and `workflow` access.

## BC-SECURITY/Empire Public Release Process
### 1. Start Release
Start a release by running the `Public - Create Release Branch` manual workflow. It doesn't matter which branch it runs on.
For the workflow input, provide the tag name that you want to release. If starkiller needs to be updated, provide a `starkillerVersion` input. The value provided should be a git tag.

The workflow will then checkout the chosen tag from the `sponsors` repo, create a release branch, push it to the public repo, and create a pull request into `main`.

The chosen tag should end in `-private`

### 2. Manual Steps - Merge release PR
Once the first workflow runs, it will open one pull request from the `release/v{version}` branch to `main`.

Check the changelog on this branch, this will be the changelog that is used for the release notes.

Merge the pull request. **DO NOT SQUASH**

**Note**: If at this point there are additional changes for the release, merge them into the release branch, not
the `main` branch. This will ensure the change ends up in the release properly.

### 3. Tag Release
Once the pull request is merged, the `Public - Tag Release` workflow will automatically run.
The workflow will create a tag and release on the `HEAD` of `main`, using the release notes from `CHANGELOG.md` for the body of the release.

The workflow will detect the last released tag, and use the release notes from the `CHANGELOG.md` between the last release and the current release.

### Docker Builds
The `Docker Image CI` workflow will build the docker image for the release. Pushes to `main` will update the `latest` tag.
Tagged releases will push to the corresponding tag in DockerHub.

### Setup
Requires secrets in the repo `DOCKER_USERNAME` and `DOCKER_PASSWORD` as well as `RELEASE_TOKEN` that has `repo` and `workflow` access.

## More Information
https://www.bc-security.org/using-github-actions-to-manage-ci-cd-for-empire/

## Contributing
To update the workflows if you don't have access to the `Empire-Sponsors` repo:
Merge to `main` in `Empire`, then we can cherry-pick the changes into `private-main`.

To update the workflows if you have access to the `Empire-Sponsors` repo:
Merge to `private-main` in `Empire-Sponsors`. It will automatically merge to `sponsors-main` and `kali-main` when the prerelease workflow runs. It will merge to `Empire#main` when the public release workflow runs.
