-- AudiCode Database Schema for Supabase
-- Run this in Supabase SQL Editor

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ============================================
-- JOBS TABLE
-- ============================================
CREATE TABLE IF NOT EXISTS audit_jobs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
    repo_url TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'running', 'completed', 'failed')),
    progress INTEGER DEFAULT 0 CHECK (progress >= 0 AND progress <= 100),
    score INTEGER,
    grade TEXT,
    confidence INTEGER,
    files_scanned INTEGER DEFAULT 0,
    error TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    completed_at TIMESTAMP WITH TIME ZONE
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_audit_jobs_user_id ON audit_jobs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_jobs_status ON audit_jobs(status);
CREATE INDEX IF NOT EXISTS idx_audit_jobs_created_at ON audit_jobs(created_at DESC);

-- ============================================
-- RESULTS TABLE
-- ============================================
CREATE TABLE IF NOT EXISTS audit_results (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    job_id UUID REFERENCES audit_jobs(id) ON DELETE CASCADE,
    severity TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low')),
    title TEXT NOT NULL,
    description TEXT,
    file TEXT NOT NULL,
    line INTEGER,
    code TEXT,
    fix TEXT,
    category TEXT,
    cwe TEXT,
    owasp TEXT,
    confidence INTEGER DEFAULT 75,
    is_false_positive BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_audit_results_job_id ON audit_results(job_id);
CREATE INDEX IF NOT EXISTS idx_audit_results_severity ON audit_results(severity);
CREATE INDEX IF NOT EXISTS idx_audit_results_owasp ON audit_results(owasp);

-- ============================================
-- CREDITS LEDGER TABLE
-- ============================================
CREATE TABLE IF NOT EXISTS credits_ledger (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
    action TEXT NOT NULL CHECK (action IN ('scan', 'fix', 'refund', 'purchase', 'bonus')),
    amount INTEGER NOT NULL,
    balance INTEGER NOT NULL,
    description TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_credits_ledger_user_id ON credits_ledger(user_id);
CREATE INDEX IF NOT EXISTS idx_credits_ledger_created_at ON credits_ledger(created_at DESC);

-- ============================================
-- USER PROFILES TABLE
-- ============================================
CREATE TABLE IF NOT EXISTS user_profiles (
    id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    email TEXT,
    credits INTEGER DEFAULT 50,
    scans_count INTEGER DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ============================================
-- ROW LEVEL SECURITY (RLS)
-- ============================================

-- Enable RLS
ALTER TABLE audit_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE credits_ledger ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_profiles ENABLE ROW LEVEL SECURITY;

-- Jobs: users can only see their own jobs
CREATE POLICY "Users can view own jobs" ON audit_jobs
    FOR SELECT USING (auth.uid() = user_id);

CREATE POLICY "Users can create jobs" ON audit_jobs
    FOR INSERT WITH CHECK (auth.uid() = user_id);

-- Results: users can only see results from their jobs
CREATE POLICY "Users can view own results" ON audit_results
    FOR SELECT USING (
        job_id IN (SELECT id FROM audit_jobs WHERE user_id = auth.uid())
    );

CREATE POLICY "Users can create results" ON audit_results
    FOR INSERT WITH CHECK (
        job_id IN (SELECT id FROM audit_jobs WHERE user_id = auth.uid())
    );

-- Credits: users can only see their own credits
CREATE POLICY "Users can view own credits" ON credits_ledger
    FOR SELECT USING (auth.uid() = user_id);

CREATE POLICY "Users can create credit entries" ON credits_ledger
    FOR INSERT WITH CHECK (auth.uid() = user_id);

-- Profiles
CREATE POLICY "Users can view own profile" ON user_profiles
    FOR SELECT USING (auth.uid() = id);

CREATE POLICY "Users can update own profile" ON user_profiles
    FOR UPDATE USING (auth.uid() = id);

-- ============================================
-- FUNCTION: Handle new user signup
-- ============================================
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO public.user_profiles (id, email, credits)
    VALUES (NEW.id, NEW.email, 50); -- 50 free credits for new users
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Trigger for new user creation
DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
    AFTER INSERT ON auth.users
    FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

-- ============================================
-- FUNCTION: Deduct credits for scan
-- ============================================
CREATE OR REPLACE FUNCTION public.deduct_scan_credits(user_uuid UUID, scan_cost INTEGER DEFAULT 5)
RETURNS TABLE(success BOOLEAN, new_balance INTEGER, error TEXT) AS $$
DECLARE
    current_credits INTEGER;
    new_credits INTEGER;
BEGIN
    -- Get current credits
    SELECT credits INTO current_credits
    FROM user_profiles
    WHERE id = user_uuid;
    
    IF current_credits IS NULL OR current_credits < scan_cost THEN
        RETURN QUERY SELECT FALSE, current_credits, 'Insufficient credits';
    END IF;
    
    -- Deduct credits
    UPDATE user_profiles
    SET credits = credits - scan_cost,
        scans_count = scans_count + 1,
        updated_at = NOW()
    WHERE id = user_uuid;
    
    -- Record in ledger
    INSERT INTO credits_ledger (user_id, action, amount, balance, description)
    VALUES (user_uuid, 'scan', -scan_cost, current_credits - scan_cost, 'Scan deduction');
    
    RETURN QUERY SELECT TRUE, current_credits - scan_cost, NULL;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- ============================================
-- VIEW: User dashboard
-- ============================================
CREATE OR REPLACE VIEW user_dashboard AS
SELECT 
    u.id,
    u.email,
    up.credits,
    up.scans_count,
    COUNT(DISTINCT j.id) as total_scans,
    COUNT(DISTINCT j.id) FILTER (WHERE j.status = 'completed') as completed_scans,
    MAX(j.created_at) as last_scan_at,
    MAX(j.score) FILTER (WHERE j.status = 'completed') as best_score
FROM auth.users u
JOIN user_profiles up ON u.id = up.id
LEFT JOIN audit_jobs j ON u.id = j.user_id
GROUP BY u.id, u.email, up.credits, up.scans_count;
