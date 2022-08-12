import commonjs from '@rollup/plugin-commonjs';
import resolve from '@rollup/plugin-node-resolve';
import typescript from '@rollup/plugin-typescript';

const external = [
  '@stablelib/cbor',
  '@stablelib/ed25519',
  '@stablelib/scrypt',
  '@stablelib/x25519',
  '@stablelib/xchacha20poly1305',
  '@stablelib/xsalsa20',
  'buffer',
  'base64url'
];

const cjsConfig = {
  input: 'src/index.mts',
  output: {
    file: 'lib-cjs/index.js',
    format: 'cjs'
  },
  plugins: [
    typescript({
      tsconfig: './tsconfig.json',
      compilerOptions: {
        outDir: 'lib-cjs',
        declaration: true,
        declarationDir: '.'
      }
    }),
    resolve({
      preferBuiltins: false
    }),
    commonjs()
  ],
  external
};

const esmConfig = {
  input: 'src/index.mts',
  output: {
    file: 'lib-esm/index.mjs',
    format: 'esm'
  },
  plugins: [
    typescript({
      tsconfig: './tsconfig.json',
      compilerOptions: {
        outDir: 'lib-esm',
        declaration: true,
        declarationDir: '.'
      }
    })
  ],
  external
};

export default [
  cjsConfig,
  esmConfig
];