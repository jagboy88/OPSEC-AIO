export { ready, webAssemblyAvailable } from './sodium.js';
export { CryptoUnavailableError, DecryptionError, FormatError } from './errors.js';
export { Alg, FORMAT_VERSION, KEY_LENGTH, type AlgId } from './format.js';
export {
  concatBytes,
  fromBase64Url,
  fromHex,
  toBase64Url,
  toHex,
  utf8Decode,
  utf8Encode,
} from './encoding.js';
export {
  generateKey,
  isValidId,
  isValidToken,
  randomBytes,
  randomId,
  randomToken,
} from './random.js';
export {
  open,
  seal,
  sealedLength,
  type AeadAlgorithm,
  type OpenOptions,
  type SealOptions,
} from './aead.js';
export {
  STREAM_CHUNK_OVERHEAD,
  STREAM_CHUNK_SIZE,
  STREAM_HEADER_LENGTH,
  StreamDecryptor,
  StreamEncryptor,
  streamChunkCount,
  streamCiphertextLength,
} from './stream.js';
export {
  ARGON2ID_BOUNDS,
  ARGON2ID_DEFAULT,
  ARGON2ID_SALT_LENGTH,
  WRAPPED_KEY_LENGTH,
  deriveKeyFromPassword,
  unwrapKeyWithPassword,
  wrapKeyWithPassword,
  type Argon2idParams,
} from './kdf.js';
export {
  generateSigningKeyPair,
  sign,
  signingKeyPairFromSeed,
  verify,
  type SigningKeyPair,
} from './sign.js';
export { generateKxKeyPair, kxPublicKey, x25519, type KxKeyPair } from './kx.js';
export { blake2b, constantTimeEqual, hashToken, sha256, sha512, wipe } from './hash.js';
export {
  buildShareLink,
  keyFromFragment,
  keyToFragment,
  parseFragment,
  type LinkSecret,
} from './link.js';
export {
  NOTE_PADDING_BLOCK,
  NOTE_TEXT_MAX_BYTES,
  decryptNote,
  encryptNote,
  type EncryptNoteOptions,
  type EncryptedNote,
  type OpenedNote,
} from './note.js';
export {
  DROP_META_PADDING_BLOCK,
  DROP_NAME_MAX_LENGTH,
  createDrop,
  dropChunkBounds,
  dropLayout,
  openDropHeader,
  padChunk,
  padme,
  type CreateDropOptions,
  type DropHeader,
  type DropLayout,
  type DropMeta,
  type NewDrop,
  type OpenedDrop,
} from './drop.js';
export { runSelfTest, type SelfTestResult } from './selftest.js';
export { authChallengeMessage } from './auth.js';
