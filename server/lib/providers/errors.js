export class ProviderError extends Error {
  constructor(message, provider, status = 0) {
    super(message);
    this.name = 'ProviderError';
    this.provider = provider;
    this.status = status;
  }
}