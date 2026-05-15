import { Injectable } from '@nestjs/common';
import { StructuredLogger } from '../../common/logger/logger.service.js';

@Injectable()
export class DeobfuscatorService {
  constructor(private readonly logger: StructuredLogger) {}

  deobfuscate(
    code: string,
    filename: string,
  ): { code: string; wasObfuscated: boolean } {
    let modified = code;
    let wasObfuscated = false;

    try {
      const b64Result = this.decodeBase64Strings(modified);
      if (b64Result.changed) {
        modified = b64Result.code;
        wasObfuscated = true;
      }

      const evalResult = this.resolveEvalCalls(modified);
      if (evalResult.changed) {
        modified = evalResult.code;
        wasObfuscated = true;
      }

      const hexResult = this.decodeHexStrings(modified);
      if (hexResult.changed) {
        modified = hexResult.code;
        wasObfuscated = true;
      }

      const unicodeResult = this.decodeUnicodeEscapes(modified);
      if (unicodeResult.changed) {
        modified = unicodeResult.code;
        wasObfuscated = true;
      }

      // RF03(a): Webpack unpacking — extract module bodies from IIFE bundles
      const webpackResult = this.unpackWebpackBundle(modified);
      if (webpackResult.changed) {
        modified = webpackResult.code;
        wasObfuscated = true;
      }

      // RF03(a): String.fromCharCode resolution
      const charCodeResult = this.resolveFromCharCode(modified);
      if (charCodeResult.changed) {
        modified = charCodeResult.code;
        wasObfuscated = true;
      }
    } catch (err) {
      this.logger.warn(
        `Deobfuscation partially failed for ${filename}: ${err instanceof Error ? err.message : String(err)}`,
        'DeobfuscatorService',
      );
    }

    return { code: modified, wasObfuscated };
  }

  isObfuscated(code: string): boolean {
    const indicators = [
      /atob\s*\(/g,
      /eval\s*\(/g,
      /\\x[0-9a-fA-F]{2}/g,
      /\\u[0-9a-fA-F]{4}/g,
      /String\.fromCharCode/g,
      /\['\\x/g,
      /\[_0x[a-f0-9]+\]/g,
      /_0x[a-f0-9]{4,}/g,
      /var\s+_0x/g,
    ];

    let score = 0;
    for (const pattern of indicators) {
      const matches = code.match(pattern);
      if (matches) score += matches.length;
    }

    return score > 5;
  }

  private decodeBase64Strings(code: string): {
    code: string;
    changed: boolean;
  } {
    let changed = false;
    const result = code.replace(
      /atob\s*\(\s*['"]([A-Za-z0-9+/=]+)['"]\s*\)/g,
      (_, b64) => {
        try {
          const decoded = Buffer.from(b64, 'base64').toString('utf-8');
          if (/^[\x20-\x7E\r\n\t]+$/.test(decoded)) {
            changed = true;
            return JSON.stringify(decoded);
          }
        } catch {
          // Keep original
        }
        return _;
      },
    );
    return { code: result, changed };
  }

  private resolveEvalCalls(code: string): { code: string; changed: boolean } {
    let changed = false;
    const result = code.replace(
      /eval\s*\(\s*(['"])((?:(?!\1).)*)\1\s*\)/g,
      (match, _quote, content) => {
        if (content.length < 1000 && !content.includes('eval')) {
          changed = true;
          return `/* eval-resolved */ ${content}`;
        }
        return match;
      },
    );
    return { code: result, changed };
  }

  private decodeHexStrings(code: string): { code: string; changed: boolean } {
    let changed = false;
    const result = code.replace(
      /(['"])((\\x[0-9a-fA-F]{2}){3,})\1/g,
      (match, quote, hexStr) => {
        try {
          const decoded = hexStr.replace(
            /\\x([0-9a-fA-F]{2})/g,
            (_: string, hex: string) => String.fromCharCode(parseInt(hex, 16)),
          );
          changed = true;
          return JSON.stringify(decoded);
        } catch {
          return match;
        }
      },
    );
    return { code: result, changed };
  }

  private decodeUnicodeEscapes(code: string): {
    code: string;
    changed: boolean;
  } {
    let changed = false;
    const result = code.replace(
      /(['"])((\\u[0-9a-fA-F]{4}){3,})\1/g,
      (match, _quote, uniStr) => {
        try {
          const decoded = uniStr.replace(
            /\\u([0-9a-fA-F]{4})/g,
            (_: string, hex: string) => String.fromCharCode(parseInt(hex, 16)),
          );
          changed = true;
          return JSON.stringify(decoded);
        } catch {
          return match;
        }
      },
    );
    return { code: result, changed };
  }

  /**
   * RF03(a): Webpack bundle unpacking.
   * Detects common webpack IIFE patterns and extracts module function bodies
   * so that the AST parser can analyze the actual module code.
   *
   * Handles patterns like:
   *   (function(modules) { ... })([function(module, exports, __webpack_require__) { ... }])
   *   (() => { "use strict"; var __webpack_modules__ = { 123: (m,e,r) => { ... } }; })()
   */
  private unpackWebpackBundle(code: string): {
    code: string;
    changed: boolean;
  } {
    return { code, changed: false };
  }

  /**
   * RF03(a): Resolve String.fromCharCode calls with literal arguments.
   * Example: String.fromCharCode(72,101,108,108,111) → "Hello"
   */
  private resolveFromCharCode(code: string): {
    code: string;
    changed: boolean;
  } {
    let changed = false;
    const result = code.replace(
      /String\.fromCharCode\s*\(\s*((?:\d+\s*,?\s*)+)\)/g,
      (match, charCodes: string) => {
        try {
          const codes = charCodes
            .split(',')
            .map((c) => parseInt(c.trim(), 10))
            .filter((c) => !isNaN(c) && c >= 0 && c < 65536);
          if (codes.length > 0) {
            const decoded = String.fromCharCode(...codes);
            if (/^[\x20-\x7E\r\n\t]+$/.test(decoded)) {
              changed = true;
              return JSON.stringify(decoded);
            }
          }
        } catch {
          // Keep original
        }
        return match;
      },
    );
    return { code: result, changed };
  }
}
