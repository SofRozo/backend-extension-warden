import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { EncryptionService } from '../encryption.service.js';
import { StructuredLogger } from '../../logger/logger.service.js';

describe('EncryptionService', () => {
  let service: EncryptionService;
  let configService: ConfigService;

  const TEST_KEY = 'a-very-secure-passphrase-at-least-32chars!!';

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        EncryptionService,
        StructuredLogger,
        {
          provide: ConfigService,
          useValue: {
            get: jest.fn((key: string) => {
              if (key === 'honeypot.encryptionKey') return TEST_KEY;
              return undefined;
            }),
          },
        },
      ],
    }).compile();

    service = module.get<EncryptionService>(EncryptionService);
    configService = module.get<ConfigService>(ConfigService);
  });

  describe('encrypt / decrypt round-trip', () => {
    it('should encrypt and decrypt a simple string', () => {
      const plaintext = 'Hello, World!';
      const encrypted = service.encrypt(plaintext);
      const decrypted = service.decrypt(encrypted);
      expect(decrypted).toBe(plaintext);
    });

    it('should encrypt and decrypt JSON data', () => {
      const data = JSON.stringify({ cookies: [{ name: 'session', value: 'abc123' }] });
      const encrypted = service.encrypt(data);
      const decrypted = service.decrypt(encrypted);
      expect(JSON.parse(decrypted)).toEqual(JSON.parse(data));
    });

    it('should produce different ciphertext for the same plaintext (random IV/salt)', () => {
      const plaintext = 'same input';
      const enc1 = service.encrypt(plaintext);
      const enc2 = service.encrypt(plaintext);
      expect(enc1.equals(enc2)).toBe(false);
    });

    it('should handle unicode content', () => {
      const plaintext = '日本語テスト 🔐 contraseña';
      const encrypted = service.encrypt(plaintext);
      const decrypted = service.decrypt(encrypted);
      expect(decrypted).toBe(plaintext);
    });

    it('should handle empty string', () => {
      const encrypted = service.encrypt('');
      const decrypted = service.decrypt(encrypted);
      expect(decrypted).toBe('');
    });
  });

  describe('encrypt validation', () => {
    it('should throw if encryption key is too short', () => {
      jest.spyOn(configService, 'get').mockReturnValue('short');
      expect(() => service.encrypt('test')).toThrow('at least 32 characters');
    });

    it('should throw if encryption key is not configured', () => {
      jest.spyOn(configService, 'get').mockReturnValue(undefined);
      expect(() => service.encrypt('test')).toThrow();
    });
  });

  describe('decrypt validation', () => {
    it('should throw on tampered ciphertext', () => {
      const encrypted = service.encrypt('secret data');
      // Tamper with the encrypted data
      encrypted[encrypted.length - 1] ^= 0xff;
      expect(() => service.decrypt(encrypted)).toThrow();
    });

    it('should throw if key is missing during decryption', () => {
      const encrypted = service.encrypt('test');
      jest.spyOn(configService, 'get').mockReturnValue(undefined);
      expect(() => service.decrypt(encrypted)).toThrow('not configured');
    });
  });
});
