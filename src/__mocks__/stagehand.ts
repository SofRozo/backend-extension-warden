// Jest mock for @browserbasehq/stagehand
// The real package pulls in chrome-launcher (ESM-only) which breaks Jest's CommonJS transform.
const Stagehand = jest.fn().mockImplementation(() => ({
  init: jest.fn().mockResolvedValue(undefined),
  act: jest.fn().mockResolvedValue({
    success: true,
    message: '',
    actionDescription: '',
    actions: [],
  }),
  observe: jest.fn().mockResolvedValue([]),
  extract: jest.fn().mockResolvedValue({ detectado: false, descripcion: '' }),
  close: jest.fn().mockResolvedValue(undefined),
}));

const AISdkClient = jest.fn();

module.exports = { Stagehand, AISdkClient };
