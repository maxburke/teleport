# What is teleport?

Have you ever wanted to share a password, key file, or some configuration files, with a co-worker only to realize that if you sent it by email, it'll be stuck in your sent folder and their inbox for all eternity? Or wonder who may shoulder-surf a stale chat message?

When you send a secret with Teleport, it's encrypted on the server. The encryption key and a unique claim link are given to you. These two pieces are both needed for your intended recipient to claim the secret. Teleport breaks the key and the claim link into separate parts so that they can be sent with separate tools if you wish; send the claim link over chat and the key with Signal.

Once an attempt is made to claim the secret, the secret is deleted forever, even if it fails. This may sound drastic but it means that secrets cannot be brute forced. It also means that if the secret is intercepted, you have a signal that it may be compromised and it needs to be changed.

# Is it safe?
That's a judgment call only you can make. But, you can view the source code [on GitHub](https://github.com/maxburke/teleport), and/or you can run it yourself. Unless you're Electronic Arts.

# Is it free of charge?
Yes! Unless you're Electronic Arts.
