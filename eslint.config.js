const eslint = require('@eslint/js');
const tseslint = require('typescript-eslint');
const security = require('eslint-plugin-security');
const globals = require('globals');

module.exports = tseslint.config(
  eslint.configs.recommended,
  ...tseslint.configs.strict,
  {
    files: ['src/**/*.ts'],
    ignores: ['**/*.test.ts', '**/*.spec.ts'],
    languageOptions: {
      globals: { ...globals.node },
      parserOptions: { project: './tsconfig.json' }
    },
    plugins: { security },
    rules: {
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
      '@typescript-eslint/explicit-function-return-type': 'error',
      '@typescript-eslint/no-explicit-any': 'error',
      '@typescript-eslint/prefer-readonly': 'error',
      '@typescript-eslint/prefer-nullish-coalescing': 'error',
      '@typescript-eslint/prefer-optional-chain': 'error',
      'security/detect-object-injection': 'error',
      'security/detect-non-literal-regexp': 'error',
      'security/detect-unsafe-regex': 'error',
      'security/detect-eval-with-expression': 'error',
      'security/detect-non-literal-fs-filename': 'warn',
      'security/detect-non-literal-require': 'error',
      'no-console': ['warn', { allow: ['error'] }],
      'no-eval': 'error',
      'no-implied-eval': 'error'
    }
  },
  {
    files: ['**/*.test.ts', '**/*.spec.ts'],
    languageOptions: { globals: { ...globals.node } },
    rules: {
      '@typescript-eslint/no-explicit-any': 'off',
      '@typescript-eslint/explicit-function-return-type': 'off',
      'security/detect-object-injection': 'off',
      'no-console': 'off'
    }
  },
  { ignores: ['build/', 'dist/', 'node_modules/', 'coverage/'] }
);
