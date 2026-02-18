const esbuild = require('esbuild');

esbuild.build({
  entryPoints: ['src/index.js'],
  bundle: true,
  platform: 'node',
  target: 'node20',
  outfile: 'dist/index.js',
  minify: false,
  sourcemap: false,
}).then(() => {
  console.log('Build complete: dist/index.js');
}).catch((err) => {
  console.error('Build failed:', err);
  process.exit(1);
});
