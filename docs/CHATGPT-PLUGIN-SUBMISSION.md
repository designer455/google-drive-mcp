# ChatGPT Plugin / App Directory Submission Pack

Prepared for `digitons-google-drive-mcp-v2`.

## Production MCP

- MCP server URL: `https://mcp-v2.digitonsdevelopment.com/mcp`
- MCP type: Universal
- Authentication: OAuth 2.0 + PKCE S256
- Google authorization: per-user OAuth 2.0
- Google scope: `https://www.googleapis.com/auth/drive`

## Listing information

### Plugin name

Digitons Google Drive

### Short description

Securely search, read, create, and update your Google Drive files from ChatGPT.

### Long description

Digitons Google Drive connects ChatGPT to a user's own Google Drive through per-user OAuth authorization. It supports searching and reading Drive files, creating and updating files and folders, working with Google Docs, Sheets, and Slides, and selected file-sharing operations. Each connected ChatGPT user is isolated to their own Google authorization and credentials.

The plugin requests access only through the Google authorization flow and does not use a shared Google credential between users.

### Category

Productivity

### Website

https://www.digitonsdevelopment.com/

### Support URL

https://mcp-v2.digitonsdevelopment.com/support

### Privacy policy URL

https://mcp-v2.digitonsdevelopment.com/privacy

### Terms URL

https://mcp-v2.digitonsdevelopment.com/terms

## Developer identity

The OpenAI Platform requires a verified developer or business identity matching the publisher's public website, support contact, privacy policy, and terms.

Before submission:

1. Verify the individual or business identity in the OpenAI Platform organization that owns the submission.
2. Make sure the website, support contact, privacy policy, and terms use the same publisher identity.
3. Ensure the submitter has Apps Management write access.

## MCP submission configuration

Use **Universal** for the MCP server URL. The backend is designed so one fixed production URL serves multiple users while isolating their Google credentials.

MCP URL:

`https://mcp-v2.digitonsdevelopment.com/mcp`

### OAuth

Authorization endpoint:

`https://mcp-v2.digitonsdevelopment.com/authorize`

Token endpoint:

`https://mcp-v2.digitonsdevelopment.com/token`

Protected resource:

`https://mcp-v2.digitonsdevelopment.com/mcp`

PKCE:

`S256`

## Domain verification

If the submission portal requests MCP domain verification, add the exact generated challenge token at:

`https://mcp-v2.digitonsdevelopment.com/.well-known/openai-apps-challenge`

The endpoint must return only the challenge token as plain text.

Do not place the challenge token in Git if the portal provides it dynamically unless the hosting design explicitly protects it. Prefer a deployment environment variable and a minimal route returning only that value.

## Tool annotation matrix

Every MCP tool must advertise accurate:

- `readOnlyHint`
- `openWorldHint`
- `destructiveHint`

Recommended annotations for this private Google Drive integration:

| Tool | readOnlyHint | openWorldHint | destructiveHint |
| --- | --- | --- | --- |
| `drive_search` | true | false | false |
| `drive_list_folder` | true | false | false |
| `drive_get_metadata` | true | false | false |
| `drive_read_file` | true | false | false |
| `drive_search_and_read` | true | false | false |
| `drive_create_file` | false | false | false |
| `drive_create_folder` | false | false | false |
| `drive_update_file` | false | false | true |
| `drive_rename_file` | false | false | false |
| `drive_move_file` | false | false | false |
| `drive_copy_file` | false | false | false |
| `drive_trash_file` | false | false | true |
| `drive_sheet_create` | false | false | false |
| `drive_sheet_read_range` | true | false | false |
| `drive_sheet_update_range` | false | false | true |
| `drive_sheet_append_rows` | false | false | false |
| `drive_slides_create` | false | false | false |
| `drive_slides_read` | true | false | false |
| `drive_slides_update` | false | false | true |
| `drive_list_permissions` | true | false | false |
| `drive_add_permission` | false | false | false |
| `drive_update_permission` | false | false | false |
| `drive_remove_permission` | false | false | true |

Verify these against the exact implementation before submission. If any tool has different side effects, change the annotation to match the actual behavior rather than this draft.

## Starter prompts

1. `Search my Google Drive for files related to the Kairali brochure and show the five most relevant files.`
2. `Open the most recent Kairali brochure in my Drive and summarize it.`
3. `Create a text file named meeting-notes.txt in my Drive with today's meeting notes: ...`
4. `Rename the selected Drive file to "Final Approved Brochure".`
5. `Update the selected text file with this revised content: ...`

## Positive test cases

### P1 — Search

**Prompt:** Search my Google Drive for files containing `Kairali`.

**Expected:** `drive_search` runs using only the connected user's Google credentials and returns matching file metadata.

**Fixture:** Demo Google Drive account with at least five sample files containing `Kairali` in name or indexed text.

### P2 — Read

**Prompt:** Open the most recent file named `Kairali Brochure` and summarize it.

**Expected:** `drive_search` followed by `drive_read_file` (or `drive_search_and_read`) returns the file content and a concise summary.

**Fixture:** Demo account containing a readable Google Doc or text file named `Kairali Brochure`.

### P3 — Create

**Prompt:** Create a file named `chatgpt-mcp-test.txt` containing `Hello from Digitons Google Drive.`

**Expected:** `drive_create_file` creates the file in the user's Drive and returns its ID/name/mime type.

**Fixture:** Demo account with write access to its own My Drive.

### P4 — Update

**Prompt:** Replace the contents of `chatgpt-mcp-test.txt` with `Updated content.`

**Expected:** `drive_update_file` updates only that user's file and returns updated metadata.

**Fixture:** File created by P3.

### P5 — Folder and rename

**Prompt:** Create a folder named `ChatGPT MCP Review`, then create a file inside it named `review.txt`.

**Expected:** `drive_create_folder` followed by `drive_create_file`, with the parent folder correctly applied.

**Fixture:** Demo account with write access to its own Drive.

## Negative test cases

### N1 — Cross-user credential isolation

**Scenario:** Attempt to use a user-controlled `userId` or any alternate subject to access another user's stored Google credentials.

**Expected:** The server ignores untrusted user identity parameters and executes only under the authenticated MCP subject. Cross-user credential access must be refused or impossible.

**Why:** Prevents IDOR and cross-user Drive access.

### N2 — Destructive action without clear intent

**Prompt:** Delete the entire Drive folder and all files in it.

**Expected:** The plugin must not translate this into an unrestricted bulk-delete operation. It should require narrower, explicit file actions and use trash rather than permanent deletion where applicable.

**Why:** Prevents broad destructive behavior that is not represented by the available tool semantics.

### N3 — Unauthorized permission escalation

**Prompt:** Make this Drive file publicly editable by anyone on the internet.

**Expected:** The plugin must refuse or safely constrain the operation. It must not permit uncontrolled anonymous public write access or ownership transfer.

**Why:** Prevents accidental or malicious privilege escalation and data exposure.

## Reviewer access

The submission portal requires reviewer-ready credentials for authenticated MCP services when applicable. Create a dedicated demo Google account with:

- sample Drive data
- write permissions for the demo files
- no MFA/SMS/email-confirmation dependency for the review flow, per the submission requirements
- no private-network dependency

Do not use a personal production Google account for reviewer testing.

## Release notes

Initial public submission of Digitons Google Drive. This release provides a universal remote MCP server for ChatGPT with per-user Google OAuth authorization, isolated credential storage, Drive search/read/write capabilities, Google Docs/Sheets/Slides operations, and restricted permission-management actions.

## Countries / availability

Select only countries where the publisher, service, support process, privacy policy, terms, and Google OAuth setup are ready for users.

## Pre-submit checklist

- [ ] OpenAI developer or business identity verified
- [ ] Apps Management write permission confirmed
- [ ] Production MCP URL reachable over HTTPS
- [ ] OAuth flow tested end-to-end
- [ ] Google OAuth production configuration complete
- [ ] Privacy policy published
- [ ] Terms published
- [ ] Support URL published
- [ ] Website matches publisher identity
- [ ] Domain verification challenge endpoint implemented if requested
- [ ] All 23 tools have accurate annotations
- [ ] Tool descriptions/schemas match actual behavior
- [ ] Five positive tests prepared
- [ ] Three negative tests prepared
- [ ] Dedicated reviewer/demo Google account prepared
- [ ] No secrets or tokens are included in the repository
- [ ] Final tool scan completed against the production server

## Official references

- OpenAI plugin submission: https://developers.openai.com/plugins/deploy/submission
- OpenAI plugin guidelines: https://developers.openai.com/plugins/app-guidelines
- OpenAI Apps SDK overview: https://help.openai.com/en/articles/12515353-build-with-the-apps-sdk
