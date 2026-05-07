// Jest mock for @ai-sdk/openai-compatible
const createOpenAICompatible = jest.fn().mockReturnValue({
  chatModel: jest.fn().mockReturnValue({}),
  languageModel: jest.fn().mockReturnValue({}),
});

module.exports = { createOpenAICompatible };
