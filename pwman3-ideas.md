# pwman3 ideas

Complete rewrite in Rust.

## Dependencies

Minimized deps.

crates:

- regex
- clap? Write our own simple cmd parser instead?
- hmac? Need mac?
- aes-gcm? gcm is probably not usable. Prefer xts?
- aes?
- xts-mode?
- subtle?

## Crypto

- Alg: AES256
- Mode: XTS
- Kdf: argon2id

## Database format

- Header (plain)
	- magic
	- version
	- reserved space
- first level secrets (encrypted)
	- header:
		- second level start offset
		- second level key part
		- reserved space
	- tree
		- TODO
	- entry[x]:
		- record length
		- tree path?
		- attributes
			- attr-type
			- attr-name offset,numchunks (can be none)
			- attr-value offset,numchunks
	- TODO end marker or num entries
	- TODO can we make this hierarchial (path)?
	- second level secrets (encrypted with second key)
		- header:
			- next alloc offset
		- chunk[x]:
			- header:
				- length
			- payload

Database: append-only + gc

Deletion: zeroing of chunks

Garbage collector: Can be done without decrypting the secrets chunks.
Only Meta decryption is needed and secrets header decryption.

If a chunk grows and doesn't fit anymore: Delete (zero-out) and append.

DB chunk size = multiple of cipher block size (16 bytes)

Mechanism for allocation of new meta space.
Keep a certain amount of unallocated space.
Move secrets, if needed (update start offset).
