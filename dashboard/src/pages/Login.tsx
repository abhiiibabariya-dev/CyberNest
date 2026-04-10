import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Eye, EyeOff, Shield, AlertCircle, Loader2, KeyRound } from 'lucide-react';
import { useStore } from '../store';
import { api } from '../services/api';

export default function Login() {
  const navigate = useNavigate();
  const setUser = useStore((s) => s.setUser);
  const user = useStore((s) => s.user);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [totpCode, setTotpCode] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [mfaRequired, setMfaRequired] = useState(false);

  useEffect(() => {
    if (user) navigate('/');
  }, [user, navigate]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      const payload: Record<string, string> = { username, password };
      if (mfaRequired && totpCode) {
        payload.totp_code = totpCode;
      }

      const res = await api.login(username, password);
      api.setToken(res.access_token);
      if (res.refresh_token) {
        localStorage.setItem('refresh_token', res.refresh_token);
      }
      setUser(res.user);
      navigate('/');
    } catch (err: any) {
      const msg = err?.message || err?.response?.data?.detail || 'Login failed';
      if (typeof msg === 'string' && (msg.toLowerCase().includes('mfa') || msg.toLowerCase().includes('totp'))) {
        setMfaRequired(true);
        setError('Enter your authenticator code to continue');
      } else {
        setError(msg);
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-[#0d1117] relative overflow-hidden">
      {/* Animated background grid */}
      <div className="absolute inset-0 opacity-5">
        <div
          className="absolute inset-0"
          style={{
            backgroundImage:
              'linear-gradient(#00d4ff 1px, transparent 1px), linear-gradient(90deg, #00d4ff 1px, transparent 1px)',
            backgroundSize: '50px 50px',
          }}
        />
      </div>

      {/* Glowing orbs */}
      <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-[#00d4ff] rounded-full opacity-[0.03] blur-3xl" />
      <div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-[#00ff88] rounded-full opacity-[0.02] blur-3xl" />

      <div className="relative z-10 w-full max-w-md px-6">
        {/* Logo */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-20 h-20 rounded-2xl bg-gradient-to-br from-[#00d4ff]/20 to-[#00d4ff]/5 border border-[#00d4ff]/30 mb-4">
            <Shield className="w-10 h-10 text-[#00d4ff]" />
          </div>
          <h1 className="text-3xl font-bold text-white tracking-tight">
            Cyber<span className="text-[#00d4ff]">Nest</span>
          </h1>
          <p className="text-[#8b949e] mt-2 text-sm tracking-widest uppercase">
            Detect. Respond. Protect.
          </p>
        </div>

        {/* Login card */}
        <div className="bg-[#161b22] border border-[#30363d] rounded-xl p-8 shadow-2xl shadow-black/50">
          <h2 className="text-lg font-semibold text-white mb-6">Sign in to your account</h2>

          {error && (
            <div
              className={`flex items-center gap-2 p-3 rounded-lg mb-4 text-sm ${
                mfaRequired && !error.toLowerCase().includes('failed')
                  ? 'bg-[#00d4ff]/10 border border-[#00d4ff]/30 text-[#00d4ff]'
                  : 'bg-red-500/10 border border-red-500/30 text-red-400'
              }`}
            >
              <AlertCircle className="w-4 h-4 flex-shrink-0" />
              <span>{error}</span>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-5">
            {/* Username */}
            <div>
              <label className="block text-sm font-medium text-[#8b949e] mb-1.5">Username</label>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="Enter your username"
                required
                autoFocus
                className="w-full px-4 py-2.5 bg-[#0d1117] border border-[#30363d] rounded-lg text-white placeholder-[#484f58] focus:outline-none focus:border-[#00d4ff] focus:ring-1 focus:ring-[#00d4ff]/50 transition-colors"
              />
            </div>

            {/* Password */}
            <div>
              <label className="block text-sm font-medium text-[#8b949e] mb-1.5">Password</label>
              <div className="relative">
                <input
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Enter your password"
                  required
                  className="w-full px-4 py-2.5 bg-[#0d1117] border border-[#30363d] rounded-lg text-white placeholder-[#484f58] focus:outline-none focus:border-[#00d4ff] focus:ring-1 focus:ring-[#00d4ff]/50 transition-colors pr-12"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-[#484f58] hover:text-[#8b949e] transition-colors"
                >
                  {showPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                </button>
              </div>
            </div>

            {/* TOTP Code */}
            {mfaRequired && (
              <div>
                <label className="block text-sm font-medium text-[#8b949e] mb-1.5">
                  <KeyRound className="w-4 h-4 inline mr-1" />
                  Authenticator Code
                </label>
                <input
                  type="text"
                  value={totpCode}
                  onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                  placeholder="000000"
                  maxLength={6}
                  autoFocus
                  className="w-full px-4 py-2.5 bg-[#0d1117] border border-[#30363d] rounded-lg text-white text-center text-2xl tracking-[0.5em] font-mono placeholder-[#484f58] focus:outline-none focus:border-[#00d4ff] focus:ring-1 focus:ring-[#00d4ff]/50 transition-colors"
                />
              </div>
            )}

            {/* Submit */}
            <button
              type="submit"
              disabled={loading}
              className="w-full py-2.5 px-4 bg-[#00d4ff] hover:bg-[#00bce0] text-[#0d1117] font-semibold rounded-lg transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
            >
              {loading ? (
                <>
                  <Loader2 className="w-5 h-5 animate-spin" />
                  Authenticating...
                </>
              ) : (
                'Sign In'
              )}
            </button>
          </form>

          {/* Divider */}
          <div className="mt-6 pt-4 border-t border-[#30363d]">
            <p className="text-xs text-[#484f58] text-center">
              Default credentials: <span className="text-[#8b949e]">admin</span> /{' '}
              <span className="text-[#8b949e]">CyberNest@2025!</span>
            </p>
          </div>
        </div>

        {/* Footer */}
        <p className="text-center text-[#484f58] text-xs mt-6">
          CyberNest SIEM + SOAR Platform &copy; {new Date().getFullYear()}
        </p>
      </div>
    </div>
  );
}
