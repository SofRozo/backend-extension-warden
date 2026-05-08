import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as crypto from 'crypto';
import * as fs from 'fs';
import { StructuredLogger } from '../logger/logger.service.js';

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 16;
const AUTH_TAG_LENGTH = 16;
const SALT_LENGTH = 32;
const KEY_ITERATIONS = 100000;
const KEY_LENGTH = 32;

/**
 * §11: AES-256-GCM encryption for storageState files.
 * StorageState files contain session cookies for honeypot accounts
 * and MUST be stored encrypted at rest in a vault separated from the main system.
 */
@Injectable()
export class EncryptionService {
  constructor(
    private readonly config: ConfigService,
    private readonly logger: StructuredLogger,
  ) {}

  private deriveKey(passphrase: string, salt: Buffer): Buffer {
    return crypto.pbkdf2Sync(
      passphrase,
      salt,
      KEY_ITERATIONS,
      KEY_LENGTH,
      'sha512',
    );
  }

  encrypt(plaintext: string): Buffer {
    const passphrase = this.config.get<string>('honeypot.encryptionKey');
    if (!passphrase || passphrase.length < 32) {
      throw new Error(
        'HONEYPOT_ENCRYPTION_KEY must be at least 32 characters (§11 compliance)',
      );
    }

    const salt = crypto.randomBytes(SALT_LENGTH);
    const key = this.deriveKey(passphrase, salt);
    const iv = crypto.randomBytes(IV_LENGTH);

    const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
    const encrypted = Buffer.concat([
      cipher.update(plaintext, 'utf-8'),
      cipher.final(),
    ]);
    const authTag = cipher.getAuthTag();

    // Format: salt(32) + iv(16) + authTag(16) + encrypted(variable)
    return Buffer.concat([salt, iv, authTag, encrypted]);
  }

  decrypt(data: Buffer): string {
    const passphrase = this.config.get<string>('honeypot.encryptionKey');
    if (!passphrase) {
      throw new Error('HONEYPOT_ENCRYPTION_KEY not configured');
    }

    const salt = data.subarray(0, SALT_LENGTH);
    const iv = data.subarray(SALT_LENGTH, SALT_LENGTH + IV_LENGTH);
    const authTag = data.subarray(
      SALT_LENGTH + IV_LENGTH,
      SALT_LENGTH + IV_LENGTH + AUTH_TAG_LENGTH,
    );
    const encrypted = data.subarray(SALT_LENGTH + IV_LENGTH + AUTH_TAG_LENGTH);

    const key = this.deriveKey(passphrase, salt);

    const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
    decipher.setAuthTag(authTag);

    return Buffer.concat([
      decipher.update(encrypted),
      decipher.final(),
    ]).toString('utf-8');
  }

  /**
   * Encrypt and save a storageState JSON file to disk.
   */
  encryptAndSaveState(statePath: string, stateData: object): void {
    const plaintext = JSON.stringify(stateData);
    const encrypted = this.encrypt(plaintext);
    fs.writeFileSync(statePath, encrypted);
    this.logger.log(
      `StorageState encrypted and saved: ${statePath}`,
      'EncryptionService',
    );
  }

  /**
   * Load and decrypt a storageState JSON file from disk.
   */
  loadAndDecryptState(statePath: string): object {
    if (!fs.existsSync(statePath)) {
      throw new Error(`StorageState file not found: ${statePath}`);
    }
    const encrypted = fs.readFileSync(statePath);
    const plaintext = this.decrypt(encrypted);
    return JSON.parse(plaintext) as object;
  }
}
