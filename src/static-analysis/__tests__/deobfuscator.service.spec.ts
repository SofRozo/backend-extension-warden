import { Test, TestingModule } from '@nestjs/testing';
import { DeobfuscatorService } from '../deobfuscator/deobfuscator.service.js';
import { StructuredLogger } from '../../common/logger/logger.service.js';

describe('DeobfuscatorService', () => {
  let service: DeobfuscatorService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [DeobfuscatorService, StructuredLogger],
    }).compile();

    service = module.get<DeobfuscatorService>(DeobfuscatorService);
  });

  describe('isObfuscated', () => {
    it('should detect eval() usage as obfuscated', () => {
      const code = `eval('alert(1)'); eval('x=1'); eval('y=2'); eval('z=3'); eval('a=5'); eval('b=6');`;
      expect(service.isObfuscated(code)).toBe(true);
    });

    it('should detect _0x variables as obfuscated', () => {
      const code = `var _0x1a2b=['string1'];var _0x3c4d=['str2'];var _0x5e6f=['str3'];_0x1a2b;_0x3c4d;_0x5e6f;_0x1a2b;_0x3c4d;_0x5e6f;`;
      expect(service.isObfuscated(code)).toBe(true);
    });

    it('should not flag clean code as obfuscated', () => {
      const code = `function greet(name) { return 'Hello, ' + name; }`;
      expect(service.isObfuscated(code)).toBe(false);
    });

    it('should detect atob usage', () => {
      const code = Array(10).fill(`atob('SGVsbG8=')`).join(';');
      expect(service.isObfuscated(code)).toBe(true);
    });
  });

  describe('deobfuscate', () => {
    it('should decode Base64 atob() calls', () => {
      // "Hello" in base64
      const code = `var x = atob('SGVsbG8=');`;
      const { code: result, wasObfuscated } = service.deobfuscate(
        code,
        'test.js',
      );
      expect(wasObfuscated).toBe(true);
      expect(result).toContain('Hello');
    });

    it('should decode hex-escaped strings', () => {
      const code = `var s = '\\x48\\x65\\x6c\\x6c\\x6f\\x57\\x6f\\x72\\x6c\\x64';`;
      const { code: result, wasObfuscated } = service.deobfuscate(
        code,
        'test.js',
      );
      expect(wasObfuscated).toBe(true);
      expect(result).toContain('HelloWorld');
    });

    it('should return original code when nothing to deobfuscate', () => {
      const code = `console.log('clean code');`;
      const { code: result, wasObfuscated } = service.deobfuscate(
        code,
        'test.js',
      );
      expect(wasObfuscated).toBe(false);
      expect(result).toBe(code);
    });

    it('should handle malformed Base64 gracefully', () => {
      const code = `var x = atob('not-valid-base64!!!');`;
      expect(() => service.deobfuscate(code, 'test.js')).not.toThrow();
    });
  });
});
