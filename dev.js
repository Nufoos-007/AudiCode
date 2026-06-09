import { spawn } from 'child_process';

const args = process.argv.slice(2);
const cleanArgs = [];

for (let i = 0; i < args.length; i++) {
  const arg = args[i];
  if (arg === '--host') {
    cleanArgs.push('-H', args[i + 1]);
    i++;
  } else if (arg.startsWith('--host=')) {
    const val = arg.split('=')[1];
    cleanArgs.push('-H', val);
  } else if (arg === '--port') {
    cleanArgs.push('-p', args[i + 1]);
    i++;
  } else if (arg.startsWith('--port=')) {
    const val = arg.split('=')[1];
    cleanArgs.push('-p', val);
  } else {
    cleanArgs.push(arg);
  }
}

console.log('[Dev Server Wrapper] Redirecting command to next dev with arguments:', cleanArgs);

const child = spawn('npx', ['next', 'dev', ...cleanArgs], {
  stdio: 'inherit',
  shell: true
});

child.on('close', (code) => {
  process.exit(code || 0);
});
