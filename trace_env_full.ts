import dotenv from 'dotenv';
dotenv.config();

console.log('--- BACKEND SERVICE (process.env) ---');
console.log('SUPABASE_URL:', process.env.SUPABASE_URL);
console.log('SUPABASE_ANON_KEY (10 chars):', process.env.SUPABASE_ANON_KEY ? process.env.SUPABASE_ANON_KEY.substring(0, 10) : 'none');
console.log('VITE_SUPABASE_URL:', process.env.VITE_SUPABASE_URL);
console.log('VITE_SUPABASE_ANON_KEY (10 chars):', process.env.VITE_SUPABASE_ANON_KEY ? process.env.VITE_SUPABASE_ANON_KEY.substring(0, 10) : 'none');

// Let's decode the JWT project reference from the anon key or check their values
const decodeSbKey = (key: string | undefined) => {
  if (!key) return 'none';
  try {
    const parts = key.split('.');
    if (parts.length === 3) {
      const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString('utf8'));
      return JSON.stringify(payload);
    }
  } catch (e: any) {
    return 'error decoding: ' + e.message;
  }
  return 'not a standard 3-part JWT';
};

console.log('SUPABASE_ANON_KEY Decoded (JWT Payload):', decodeSbKey(process.env.SUPABASE_ANON_KEY));
console.log('VITE_SUPABASE_ANON_KEY Decoded (JWT Payload):', decodeSbKey(process.env.VITE_SUPABASE_ANON_KEY));
