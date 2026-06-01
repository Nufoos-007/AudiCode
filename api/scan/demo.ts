export const DEMO_REPOSITORIES = [
  {
    id: 'demo-auth-service',
    name: 'auth-and-dashboard-service',
    owner: 'audicode-sandbox',
    description: 'Core login microservice with raw database connections and system shell tools.',
    isPrivate: true,
    defaultBranch: 'main',
    url: 'https://github.com/audicode-sandbox/auth-and-dashboard-service'
  },
  {
    id: 'demo-react-app',
    name: 'vulnerable-react-dashboard',
    owner: 'audicode-sandbox',
    description: 'Standard single-page interface with dynamic property parameters, DOM injections, and package lockfiles.',
    isPrivate: false,
    defaultBranch: 'master',
    url: 'https://github.com/audicode-sandbox/vulnerable-react-dashboard'
  },
  {
    id: 'demo-validation-suite',
    name: 'scanner-validation-suite',
    owner: 'audicode-sandbox',
    description: 'Validation suite testing Code Injection, SQL Injection, XSS, Command Injection, Secrets, and equivalent sanitized/secure patterns.',
    isPrivate: false,
    defaultBranch: 'main',
    url: 'https://github.com/audicode-sandbox/scanner-validation-suite'
  }
];

export const DEMO_FILES: Record<string, { path: string; content: string }[]> = {
  'demo-auth-service': [
    {
      path: 'package.json',
      content: `{
  "name": "auth-service",
  "dependencies": {
    "express": "4.16.0",
    "lodash": "4.17.15",
    "jsonwebtoken": "8.5.1"
  }
}`
    },
    {
      path: 'src/routes/auth.ts',
      content: `import { Request, Response } from 'express';

export async function loginRoute(req: Request, res: Response) {
  const email = req.query.email;
  const password = req.query.password;
  const sqlQuery = "SELECT * FROM users WHERE email = '" + email + "' AND password = '" + password + "'";
  db.execute(sqlQuery, (err, results) => {
    if (err) return res.status(500).send(err);
    res.json({ success: true, user: results[0] });
  });
}`
    },
    {
      path: 'src/config/keys.ts',
      content: `export const AWS_ACCESS_KEY_ID = "AKIA1234567890ABCDEF";
export const APP_SECRET = "github_pat_82charsLongSecretAccessTokenThatShouldNotBeCommittedInTheSourceCode_abcdef123";`
    },
    {
      path: 'src/utils/backup.py',
      content: `import os
      import sys
      
      def create_archive():
          target_dir = sys.argv[1]
          cmd = "tar -czf backup.tar.gz " + target_dir
          os.system(cmd)`
    }
  ],
  'demo-react-app': [
    {
      path: 'package.json',
      content: `{
  "name": "react-app",
  "dependencies": {
    "react": "^18.2.0",
    "axios": "0.21.1",
    "moment": "2.29.1"
  }
}`
    },
    {
      path: 'src/components/Renderer.tsx',
      content: `import React from 'react';

export default function DocumentRenderer() {
  const contentQuery = new URLSearchParams(window.location.search).get('html');
  return (
    <div className="renderer-container">
      <h3>Dynamic preview</h3>
      <div dangerouslySetInnerHTML={{ __html: contentQuery }} />
    </div>
  );
}`
    },
    {
      path: 'src/utils/evaluator.js',
      content: `function processFormula(req) {
  const codeString = req.query.formula;
  return eval(codeString);
}`
    }
  ],
  'demo-validation-suite': [
    {
      path: 'package.json',
      content: `{
  "name": "scanner-validation-suite",
  "dependencies": {
    "lodash": "4.17.15",
    "moment": "2.29.1"
  }
}`
    },
    {
      path: 'src/vulnerable/code-injection.ts',
      content: `import { Request, Response } from 'express';

export function runFormula(req: Request, res: Response) {
  const code = req.query.code;
  const result = eval(code);
  return result;
}`
    },
    {
      path: 'src/vulnerable/sql-injection.ts',
      content: `import { Request, Response } from 'express';

export function getProfile(req: Request, res: Response) {
  const userId = req.query.id;
  const queryStr = "SELECT * FROM users WHERE id = '" + userId + "'";
  db.execute(queryStr);
}`
    },
    {
      path: 'src/vulnerable/xss.tsx',
      content: `import React from 'react';

export function RenderPage() {
  const payload = new URLSearchParams(window.location.search).get('html');
  const container = document.getElementById('output');
  container.innerHTML = payload;
}`
    },
    {
      path: 'src/vulnerable/command-injection.ts',
      content: `import { Request, Response } from 'express';
import { exec } from 'child_process';

export function pingServer(req: Request, res: Response) {
  const host = req.query.host;
  const cmd = "ping -c 3 " + host;
  exec(cmd, (err, stdout) => {
    res.send(stdout);
  });
}`
    },
    {
      path: 'src/vulnerable/backup.py',
      content: `import os
import sys

def build_backup():
    target_dir = sys.argv[1]
    cmd = "tar -czf backup.tar.gz " + target_dir
    os.system(cmd)`
    }
  ]
};
