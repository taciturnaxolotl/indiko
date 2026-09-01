---
title: about indiko
subtitle: what this server is, who runs it, and what it is for
description: Indiko is an open-source, self-hosted IndieAuth and OAuth 2.0 provider run by Kieran Klukas for the dunkirk.sh homelab and side projects.
---

Indiko is an identity provider written by [Kieran Klukas](https://dunkirk.sh) in Westerville, Ohio. It started as a way to sign in to a homelab without running a heavyweight identity stack, and it grew into a full IndieAuth, OAuth 2.0, and OpenID Connect server that other projects can integrate with.

## the shape of the project

The whole server is a single Bun process backed by one SQLite file. There is no external session store, no message queue, and no build step at runtime. Keeping it small is deliberate: an identity provider is the one service you cannot afford to have go mysteriously wrong at three in the morning, so it should be small enough to read end to end.

Authentication is passkeys only. There is no password field to phish, no password reset flow to abuse, and no password hash to leak. Passkeys are registered as discoverable credentials, so password managers and platform authenticators can offer them without a username hint. People can register several passkeys and name each one.

## what runs on it

This instance, `indiko.dunkirk.sh`, is the authentication provider for the homelab and side projects at `dunkirk.sh`. It is a personal deployment rather than a hosted product: accounts are invite-only, and there is no sign-up form. If you want Indiko for yourself, run your own copy. The code is open source under the license in the repository, and the install steps are short.

## standards it follows

Indiko implements IndieAuth, OAuth 2.0 authorization code flow with PKCE, the OAuth 2.0 device authorization grant, dynamic client registration, token introspection and revocation, resource indicators, and OpenID Connect discovery with RS256 ID tokens. Where a specification offers a choice, Indiko picks the strict option: S256 code challenges only, single-use codes with a sixty second lifetime, and consent that is re-asked whenever an app requests something new.

The canonical repository is [`@dunkirk.sh/indiko` on tangled](https://tangled.org/@dunkirk.sh/indiko), with a mirror on [GitHub](https://github.com/taciturnaxolotl/indiko). See the [documentation](/docs) for integration details, or the [contact page](/contact) to get in touch.
