import { defineConfig } from '@hey-api/openapi-ts';

// Regenerates the TS client and types from apps/api's OpenAPI 3.1 spec.
// CI checks that the committed files match (anti-drift with the Go code).
export default defineConfig({
  input: './openapi.yaml',
  output: {
    path: './src/gen',
  },
  plugins: ['@hey-api/typescript', '@hey-api/client-fetch'],
});
