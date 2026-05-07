import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { DownloaderService } from '../downloader.service.js';
import { StructuredLogger } from '../../common/logger/logger.service.js';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as crypto from 'crypto';

describe('DownloaderService', () => {
  let service: DownloaderService;
  let tempDir: string;

  beforeEach(async () => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ext-sandbox-test-'));

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        DownloaderService,
        StructuredLogger,
        {
          provide: ConfigService,
          useValue: {
            get: jest.fn((key: string) => {
              if (key === 'analysis.crxDownloadDir') return path.join(tempDir, 'crx');
              if (key === 'analysis.extractDir') return path.join(tempDir, 'extracted');
              return undefined;
            }),
          },
        },
      ],
    }).compile();

    service = module.get<DownloaderService>(DownloaderService);
  });

  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  describe('cleanup', () => {
    it('should remove CRX file and extract directory', () => {
      const crxDir = path.join(tempDir, 'crx');
      const extractDir = path.join(tempDir, 'extracted');
      fs.mkdirSync(crxDir, { recursive: true });
      fs.mkdirSync(extractDir, { recursive: true });

      const crxPath = path.join(crxDir, 'test-ext.crx');
      const extPath = path.join(extractDir, 'test-ext');
      fs.writeFileSync(crxPath, 'dummy');
      fs.mkdirSync(extPath, { recursive: true });
      fs.writeFileSync(path.join(extPath, 'manifest.json'), '{}');

      service.cleanup('test-ext');

      expect(fs.existsSync(crxPath)).toBe(false);
      expect(fs.existsSync(extPath)).toBe(false);
    });

    it('should not throw when files do not exist', () => {
      expect(() => service.cleanup('nonexistent')).not.toThrow();
    });
  });

  describe('downloadAndExtract', () => {
    it('should fail when all download methods fail (no network)', async () => {
      await expect(
        service.downloadAndExtract('invalid-ext-id-xyz', 'job-test'),
      ).rejects.toThrow('Failed to download CRX');
    }, 60000);
  });
});
