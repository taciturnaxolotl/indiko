---
title: privacy
subtitle: what indiko stores, why, and for how long
description: What data the Indiko identity provider stores, why it is stored, how long it is kept, and how to delete an account.
---

Indiko is an identity provider, so the data it holds is deliberately small: enough to prove who you are to the apps you approve, and nothing else. This page describes the instance running at `indiko.dunkirk.sh`. Self-hosted copies are governed by whoever runs them.

## what is stored

- **Profile.** Your username, display name, and optionally an email address, avatar URL, and website URL. These are the values apps receive when you grant the `profile` or `email` scope.
- **Passkeys.** A credential ID, a public key, a signature counter, and a name you choose for each device. Private keys never leave your device and are never sent to this server.
- **Sessions.** A session token and expiry, so you are not asked to authenticate on every page.
- **Grants.** Which applications you approved, which scopes and role you granted, and when. Access and refresh tokens issued to those applications.
- **Operational records.** Short-lived authorization codes, WebAuthn challenges, and device codes, plus server logs that may include IP addresses for rate limiting and abuse investigation.

There is no analytics, no advertising, no third-party tracking, and no profile sold or shared with anyone. Data leaves this server only when you approve an application, and then only the scopes you approved.

## how long it is kept

Authorization codes expire after sixty seconds, WebAuthn challenges after five minutes, sessions after twenty-four hours, and device codes shortly after issue. A background job sweeps expired records every hour, so they are removed rather than merely ignored. Access and refresh tokens live until they expire or you revoke the app. Profile data and passkeys persist until you delete them.

## your control over it

You can edit your profile, add or remove passkeys, and revoke any application's access from your dashboard at any time. Revoking an app deletes its tokens and its record of granted scopes immediately. Deleting your account removes your profile, passkeys, sessions, grants, and tokens from the database.

## contact

Questions about data on this instance, or a request to delete something, go to **hello@dunkirk.sh**. Security concerns go to **security@dunkirk.sh**; see the [contact page](/contact) for details. The operator is Kieran Klukas, Westerville, Ohio, United States.
