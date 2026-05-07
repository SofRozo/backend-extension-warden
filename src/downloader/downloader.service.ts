import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import * as https from 'https';
import * as http from 'http';
import AdmZip from 'adm-zip';
import { StructuredLogger } from '../common/logger/logger.service.js';

export interface DownloadResult {
  crxPath: string;
  extractPath: string;
  crxHash: string;
  manifestData: Record<string, unknown>;
}

@Injectable()
export class DownloaderService {
  constructor(
    private readonly config: ConfigService,
    private readonly logger: StructuredLogger,
  ) {}

  async downloadAndExtract(
    extensionId: string,
    jobId: string,
  ): Promise<DownloadResult> {
    const downloadDir =
      this.config.get<string>('analysis.crxDownloadDir') ||
      '/tmp/ext-sandbox/crx';
    const extractDir =
      this.config.get<string>('analysis.extractDir') ||
      '/tmp/ext-sandbox/extracted';

    fs.mkdirSync(downloadDir, { recursive: true });
    fs.mkdirSync(extractDir, { recursive: true });

    const crxPath = path.join(downloadDir, `${extensionId}.crx`);
    const extExtractPath = path.join(extractDir, extensionId);

    this.logger.logWithJob(
      jobId,
      'info',
      `Downloading CRX for extension ${extensionId}`,
      'DownloaderService',
    );

    await this.downloadCrx(extensionId, crxPath);

    const crxHash = await this.computeHash(crxPath);

    this.logger.logWithJob(
      jobId,
      'info',
      `CRX downloaded, hash: ${crxHash}`,
      'DownloaderService',
    );

    await this.extractCrx(crxPath, extExtractPath);

    const manifestPath = path.join(extExtractPath, 'manifest.json');
    let manifestData: Record<string, unknown> = {};
    if (fs.existsSync(manifestPath)) {
      manifestData = JSON.parse(fs.readFileSync(manifestPath, 'utf-8'));
    }

    return { crxPath, extractPath: extExtractPath, crxHash, manifestData };
  }

  private async downloadCrx(
    extensionId: string,
    outputPath: string,
  ): Promise<void> {
    const methods = [
      () => this.downloadFromChromeWebStore(extensionId, outputPath),
      () => this.downloadFromDirectUrl(extensionId, outputPath),
      () => this.downloadFromAlternateApi(extensionId, outputPath),
    ];

    for (let i = 0; i < methods.length; i++) {
      try {
        await methods[i]();
        if (fs.existsSync(outputPath) && fs.statSync(outputPath).size > 0) {
          this.logger.log(
            `Download succeeded with method ${i + 1}`,
            'DownloaderService',
          );
          return;
        }
      } catch (err) {
        this.logger.warn(
          `Download method ${i + 1} failed: ${err instanceof Error ? err.message : String(err)}`,
          'DownloaderService',
        );
      }
    }

    throw new Error(
      `Failed to download CRX for extension ${extensionId} using all methods`,
    );
  }

  private downloadFromChromeWebStore(
    extensionId: string,
    outputPath: string,
  ): Promise<void> {
    const url =
      `https://clients2.google.com/service/update2/crx?response=redirect&` +
      `prodversion=131.0.0.0&acceptformat=crx2,crx3&` +
      `x=id%3D${extensionId}%26uc`;
    return this.downloadFile(url, outputPath);
  }

  private downloadFromDirectUrl(
    extensionId: string,
    outputPath: string,
  ): Promise<void> {
    const url =
      `https://clients2.google.com/service/update2/crx?response=redirect&` +
      `os=win&arch=x64&os_arch=x86_64&nacl_arch=x86-64&` +
      `prod=chromecrx&prodchannel=unknown&prodversion=131.0.0.0&` +
      `acceptformat=crx2,crx3&x=id%3D${extensionId}%26uc`;
    return this.downloadFile(url, outputPath);
  }

  private downloadFromAlternateApi(
    extensionId: string,
    outputPath: string,
  ): Promise<void> {
    const url = `https://edge.microsoft.com/extensionwebstorebase/v1/crx?response=redirect&x=id%3D${extensionId}%26installsource%3Dondemand%26uc`;
    return this.downloadFile(url, outputPath);
  }

  private downloadFile(url: string, outputPath: string): Promise<void> {
    return new Promise((resolve, reject) => {
      const protocol = url.startsWith('https') ? https : http;
      const request = protocol.get(
        url,
        { headers: { 'User-Agent': 'Mozilla/5.0' }, timeout: 30000 },
        (response) => {
          if (
            response.statusCode &&
            response.statusCode >= 300 &&
            response.statusCode < 400 &&
            response.headers.location
          ) {
            this.downloadFile(response.headers.location, outputPath)
              .then(resolve)
              .catch(reject);
            return;
          }

          if (response.statusCode !== 200) {
            reject(new Error(`HTTP ${response.statusCode}`));
            return;
          }

          const file = fs.createWriteStream(outputPath);
          response.pipe(file);
          file.on('finish', () => {
            file.close();
            resolve();
          });
          file.on('error', (err) => {
            fs.unlinkSync(outputPath);
            reject(err);
          });
        },
      );
      request.on('error', reject);
      request.on('timeout', () => {
        request.destroy();
        reject(new Error('Download timeout'));
      });
    });
  }

  private async extractCrx(crxPath: string, extractPath: string): Promise<void> {
    if (fs.existsSync(extractPath)) {
      fs.rmSync(extractPath, { recursive: true, force: true });
    }
    fs.mkdirSync(extractPath, { recursive: true });

    const buffer = fs.readFileSync(crxPath);
    let zipStartOffset = 0;

    // CRX3 format: magic "Cr24" + version(4) + headerLength(4) + header
    if (
      buffer.length > 12 &&
      buffer[0] === 0x43 &&
      buffer[1] === 0x72 &&
      buffer[2] === 0x32 &&
      buffer[3] === 0x34
    ) {
      const version = buffer.readUInt32LE(4);
      if (version === 3) {
        const headerLength = buffer.readUInt32LE(8);
        zipStartOffset = 12 + headerLength;
      } else if (version === 2) {
        const pubKeyLen = buffer.readUInt32LE(8);
        const sigLen = buffer.readUInt32LE(12);
        zipStartOffset = 16 + pubKeyLen + sigLen;
      }
    }

    const zipBuffer = buffer.subarray(zipStartOffset);
    const tmpZipPath = crxPath + '.zip';
    fs.writeFileSync(tmpZipPath, zipBuffer);

    const zip = new AdmZip(tmpZipPath);
    zip.extractAllTo(extractPath, true);

    fs.unlinkSync(tmpZipPath);
  }

  private async computeHash(filePath: string): Promise<string> {
    return new Promise((resolve, reject) => {
      const hash = crypto.createHash('sha256');
      const stream = fs.createReadStream(filePath);
      stream.on('data', (data) => hash.update(data));
      stream.on('end', () => resolve(hash.digest('hex')));
      stream.on('error', reject);
    });
  }

  cleanup(extensionId: string): void {
    const downloadDir =
      this.config.get<string>('analysis.crxDownloadDir') ||
      '/tmp/ext-sandbox/crx';
    const extractDir =
      this.config.get<string>('analysis.extractDir') ||
      '/tmp/ext-sandbox/extracted';

    const crxPath = path.join(downloadDir, `${extensionId}.crx`);
    const extExtractPath = path.join(extractDir, extensionId);

    try {
      if (fs.existsSync(crxPath)) fs.unlinkSync(crxPath);
      if (fs.existsSync(extExtractPath))
        fs.rmSync(extExtractPath, { recursive: true, force: true });
    } catch {
      // Best effort cleanup
    }
  }
}
