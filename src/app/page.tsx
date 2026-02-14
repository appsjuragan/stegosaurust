'use client'

import { useState, useEffect, useCallback } from 'react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Textarea } from '@/components/ui/textarea'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Label } from '@/components/ui/label'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import { Progress } from '@/components/ui/progress'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog'
import {
  Shield,
  Lock,
  Unlock,
  Image as ImageIcon,
  QrCode,
  Key,
  Upload,
  Download,
  Eye,
  EyeOff,
  Copy,
  Check,
  AlertCircle,
  Loader2,
  User,
  LogOut,
  Menu,
  X,
  FileText,
  Trash2,
  History,
  HelpCircle
} from 'lucide-react'
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from '@/components/ui/tooltip'

// API Base URL - use relative URLs through Next.js proxy
const API_BASE = '/api'

// Types
interface User {
  id: string
  username: string
  email: string
}

interface CaptchaResponse {
  captcha_id: string
  image: string
}

interface AuthResponse {
  token: string
  expires_in: number
  user: User
}

interface Message {
  id: string
  created_at: string
  has_stegano: boolean
  original_filename: string | null
}

interface EncryptResponse {
  encrypted_data: string
  seed_hash: string
}

interface DecryptResponse {
  decrypted_text: string
}

interface EmbedResponse {
  image_data: string
  original_filename: string
  metadata_used: boolean
  overflow_size: number
  message_id: string
}

interface ExtractResponse {
  message: string
  was_encrypted: boolean
}

interface QRCodeResponse {
  qr_image: string
  data: string
  size: number
}

// Main App Component
export default function Home() {
  const [activeTab, setActiveTab] = useState('encrypt')
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)

  const [token, setToken] = useState<string | null>(null)
  const [user, setUser] = useState<User | null>(null)
  const [mounted, setMounted] = useState(false)

  // Initialize state from localStorage after mount
  useEffect(() => {
    setMounted(true)
    const savedToken = localStorage.getItem('token')
    const savedUser = localStorage.getItem('user')
    const savedTab = localStorage.getItem('activeTab')

    if (savedToken) setToken(savedToken)
    if (savedUser) {
      try {
        setUser(JSON.parse(savedUser))
      } catch (e) {
        console.error('Failed to parse user from localStorage', e)
      }
    }
    if (savedTab) {
      setActiveTab(savedTab)
    }
  }, [])

  // Clear messages after timeout
  useEffect(() => {
    if (error || success) {
      const timer = setTimeout(() => {
        setError(null)
        setSuccess(null)
      }, 5000)
      return () => clearTimeout(timer)
    }
  }, [error, success])

  const handleLogin = (authData: AuthResponse) => {
    setToken(authData.token)
    setUser(authData.user)
    localStorage.setItem('token', authData.token)
    localStorage.setItem('user', JSON.stringify(authData.user))
  }

  const handleLogout = () => {
    setToken(null)
    setUser(null)
    localStorage.removeItem('token')
    localStorage.removeItem('user')
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900">
      {/* Header */}
      <header className="sticky top-0 z-50 border-b border-slate-700 bg-slate-900/95 backdrop-blur supports-[backdrop-filter]:bg-slate-900/60">
        <div className="container mx-auto px-4">
          <div className="flex h-16 items-center justify-between">
            {/* Logo */}
            <div className="flex items-center gap-2">
              <Shield className="h-8 w-8 text-emerald-400" />
              <span className="text-xl font-bold text-white">Stegosaurust</span>
            </div>

            {/* Desktop Navigation */}
            <nav className="hidden md:flex items-center gap-4">
              {user ? (
                <>
                  <span className="text-slate-400 text-sm">Welcome, {user.username}</span>
                  <Button variant="outline" size="sm" onClick={handleLogout}>
                    <LogOut className="h-4 w-4 mr-2" />
                    Logout
                  </Button>
                </>
              ) : (
                <AuthButtons onLogin={handleLogin} setError={setError} />
              )}
              <HowToUseDialog />
            </nav>

            {/* Mobile Menu Button */}
            <Button
              variant="ghost"
              size="icon"
              className="md:hidden text-white"
              onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            >
              {mobileMenuOpen ? <X className="h-6 w-6" /> : <Menu className="h-6 w-6" />}
            </Button>
          </div>
        </div>

        {/* Mobile Menu */}
        {mobileMenuOpen && (
          <div className="md:hidden border-t border-slate-700 bg-slate-900 p-4">
            {user ? (
              <div className="space-y-4">
                <p className="text-slate-400">Welcome, {user.username}</p>
                <Button variant="outline" className="w-full" onClick={handleLogout}>
                  <LogOut className="h-4 w-4 mr-2" />
                  Logout
                </Button>
              </div>
            ) : (
              <AuthButtons onLogin={handleLogin} setError={setError} isMobile />
            )}
            <div className="pt-2 border-t border-slate-800">
              <HowToUseDialog isMobile />
            </div>
          </div>
        )}
      </header>

      {/* Main Content */}
      <main className="container mx-auto px-4 py-6 md:py-10">
        {/* Floating Toasts */}
        <div className="fixed bottom-4 right-4 z-50 flex flex-col gap-2 max-w-sm w-full pointer-events-none">
          {error && (
            <div className="pointer-events-auto animate-in slide-in-from-right-full fade-in duration-300">
              <Alert variant="destructive" className="shadow-lg border-2">
                <AlertCircle className="h-4 w-4" />
                <AlertDescription className="font-medium">{error}</AlertDescription>
              </Alert>
            </div>
          )}
          {success && (
            <div className="pointer-events-auto animate-in slide-in-from-right-full fade-in duration-300">
              <Alert className="shadow-lg border-emerald-500 bg-emerald-950/90 text-emerald-400 border-2">
                <Check className="h-4 w-4 text-emerald-400" />
                <AlertDescription className="font-medium">{success}</AlertDescription>
              </Alert>
            </div>
          )}
        </div>

        {!user ? (
          // Landing Page for Non-authenticated Users
          <div className="flex flex-col items-center justify-center py-12 md:py-20">
            <div className="text-center max-w-3xl mx-auto px-4">
              <Shield className="h-16 w-16 md:h-20 md:w-20 text-emerald-400 mx-auto mb-6" />
              <h1 className="text-3xl md:text-5xl font-bold text-white mb-4">
                Stegosaurust
              </h1>
              <p className="text-slate-400 text-base md:text-lg mb-8">
                Hide your secrets in plain sight. Encrypt your messages with seed words and embed them
                securely into images using advanced steganography techniques.
              </p>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 md:gap-6 mb-8">
                <FeatureCard
                  icon={<Lock className="h-8 w-8" />}
                  title="AES-256 Encryption"
                  description="Military-grade encryption with your seed words as the key"
                />
                <FeatureCard
                  icon={<ImageIcon className="h-8 w-8" />}
                  title="Steganography"
                  description="Hide encrypted data in PNG, JPG, and WebP images"
                />
                <FeatureCard
                  icon={<QrCode className="h-8 w-8" />}
                  title="QR Codes"
                  description="Share seed words via QR codes for easy transmission"
                />
              </div>
              <p className="text-slate-500 text-sm">
                Register or login to get started
              </p>
            </div>
          </div>
        ) : (
          // Main Application
          // Main Application
          <Tabs
            value={activeTab}
            onValueChange={(val) => {
              setActiveTab(val);
              localStorage.setItem('activeTab', val);
            }}
            className="space-y-6"
          >
            <TabsList className="w-full flex bg-transparent p-0 border-b border-slate-700 rounded-none h-auto mb-6">
              <TabsTrigger
                value="encrypt"
                className="flex-1 rounded-none border-b-2 border-transparent data-[state=active]:border-emerald-400 data-[state=active]:bg-transparent data-[state=active]:shadow-none data-[state=active]:text-emerald-400 py-3 text-slate-400 hover:text-white transition-colors"
              >
                <Tooltip delayDuration={300}>
                  <TooltipTrigger asChild>
                    <div className="flex items-center justify-center">
                      <Lock className="h-4 w-4 mr-2" />
                      <span className="hidden sm:inline">Encrypt</span>
                    </div>
                  </TooltipTrigger>
                  <TooltipContent>
                    <p>Encrypt text using AES-256</p>
                  </TooltipContent>
                </Tooltip>
              </TabsTrigger>
              <TabsTrigger
                value="decrypt"
                className="flex-1 rounded-none border-b-2 border-transparent data-[state=active]:border-emerald-400 data-[state=active]:bg-transparent data-[state=active]:shadow-none data-[state=active]:text-emerald-400 py-3 text-slate-400 hover:text-white transition-colors"
              >
                <Tooltip delayDuration={300}>
                  <TooltipTrigger asChild>
                    <div className="flex items-center justify-center">
                      <Unlock className="h-4 w-4 mr-2" />
                      <span className="hidden sm:inline">Decrypt</span>
                    </div>
                  </TooltipTrigger>
                  <TooltipContent>
                    <p>Decrypt ciphertext with seed words</p>
                  </TooltipContent>
                </Tooltip>
              </TabsTrigger>
              <TabsTrigger
                value="stegano"
                className="flex-1 rounded-none border-b-2 border-transparent data-[state=active]:border-emerald-400 data-[state=active]:bg-transparent data-[state=active]:shadow-none data-[state=active]:text-emerald-400 py-3 text-slate-400 hover:text-white transition-colors"
              >
                <Tooltip delayDuration={300}>
                  <TooltipTrigger asChild>
                    <div className="flex items-center justify-center">
                      <ImageIcon className="h-4 w-4 mr-2" />
                      <span className="hidden sm:inline">Steganography</span>
                    </div>
                  </TooltipTrigger>
                  <TooltipContent>
                    <p>Hide messages or files inside images</p>
                  </TooltipContent>
                </Tooltip>
              </TabsTrigger>
              <TabsTrigger
                value="qrcode"
                className="flex-1 rounded-none border-b-2 border-transparent data-[state=active]:border-emerald-400 data-[state=active]:bg-transparent data-[state=active]:shadow-none data-[state=active]:text-emerald-400 py-3 text-slate-400 hover:text-white transition-colors"
              >
                <QrCode className="h-4 w-4 mr-2" />
                <span className="hidden sm:inline">QR Code</span>
              </TabsTrigger>
              <TabsTrigger
                value="history"
                className="flex-1 rounded-none border-b-2 border-transparent data-[state=active]:border-emerald-400 data-[state=active]:bg-transparent data-[state=active]:shadow-none data-[state=active]:text-emerald-400 py-3 text-slate-400 hover:text-white transition-colors"
              >
                <History className="h-4 w-4 mr-2" />
                <span className="hidden sm:inline">History</span>
              </TabsTrigger>
            </TabsList>

            <TabsContent value="encrypt">
              <EncryptTab token={token!} setError={setError} setSuccess={setSuccess} />
            </TabsContent>

            <TabsContent value="stegano">
              <SteganoTab token={token!} setError={setError} setSuccess={setSuccess} />
            </TabsContent>

            <TabsContent value="qrcode">
              <QRCodeTab token={token!} setError={setError} setSuccess={setSuccess} />
            </TabsContent>

            <TabsContent value="history">
              <HistoryTab token={token!} setError={setError} setSuccess={setSuccess} />
            </TabsContent>

            <TabsContent value="decrypt">
              <DecryptTab token={token!} setError={setError} setSuccess={setSuccess} />
            </TabsContent>
          </Tabs>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-700 py-6 mt-auto">
        <div className="container mx-auto px-4 text-center text-slate-500 text-sm">
          <p>Stegosaurust - Secure Steganography Application</p>
          <p className="mt-1">Powered by AES-256 encryption and LSB steganography</p>
        </div>
      </footer>
    </div>
  )
}

// Feature Card Component
function FeatureCard({ icon, title, description }: { icon: React.ReactNode; title: string; description: string }) {
  return (
    <Card className="bg-slate-800/50 border-slate-700 text-center">
      <CardContent className="pt-6">
        <div className="text-emerald-400 mb-3 flex justify-center">{icon}</div>
        <h3 className="text-lg font-semibold text-white mb-2">{title}</h3>
        <p className="text-slate-400 text-sm">{description}</p>
      </CardContent>
    </Card>
  )
}

// Auth Buttons Component
function AuthButtons({ onLogin, setError, isMobile = false }: {
  onLogin: (auth: AuthResponse) => void
  setError: (error: string | null) => void
  isMobile?: boolean
}) {
  const [showRegister, setShowRegister] = useState(false)

  return (
    <div className={isMobile ? 'space-y-2' : 'flex gap-2'}>
      <Dialog>
        <DialogTrigger asChild>
          <Button variant="outline" size={isMobile ? 'default' : 'sm'} className={isMobile ? 'w-full' : ''}>
            <User className="h-4 w-4 mr-2" />
            Login
          </Button>
        </DialogTrigger>
        <DialogContent className="max-w-md mx-4">
          <DialogHeader>
            <DialogTitle>Login</DialogTitle>
            <DialogDescription>Enter your credentials to access your vault</DialogDescription>
          </DialogHeader>
          <AuthForm mode="login" onSuccess={onLogin} setError={setError} />
        </DialogContent>
      </Dialog>

      <Dialog>
        <DialogTrigger asChild>
          <Button size={isMobile ? 'default' : 'sm'} className={isMobile ? 'w-full' : ''}>
            Register
          </Button>
        </DialogTrigger>
        <DialogContent className="max-w-md mx-4">
          <DialogHeader>
            <DialogTitle>Create Account</DialogTitle>
            <DialogDescription>Register to start encrypting and hiding messages</DialogDescription>
          </DialogHeader>
          <AuthForm mode="register" onSuccess={onLogin} setError={setError} />
        </DialogContent>
      </Dialog>
    </div>
  )
}

// Auth Form Component
function AuthForm({ mode, onSuccess, setError }: {
  mode: 'login' | 'register'
  onSuccess: (auth: AuthResponse) => void
  setError: (error: string | null) => void
}) {
  const [username, setUsername] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [captchaId, setCaptchaId] = useState('')
  const [captchaImage, setCaptchaImage] = useState('')
  const [captchaAnswer, setCaptchaAnswer] = useState('')
  const [loading, setLoading] = useState(false)

  // Fetch captcha on mount
  useEffect(() => {
    fetchCaptcha()
  }, [])

  const fetchCaptcha = async () => {
    try {
      const response = await fetch(`${API_BASE}/captcha`)
      const data: CaptchaResponse = await response.json()
      setCaptchaId(data.captcha_id)
      setCaptchaImage(data.image)
    } catch (err) {
      setError('Failed to load captcha')
    }
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    setError(null)

    try {
      const endpoint = mode === 'login' ? '/login' : '/register'
      const body = mode === 'login'
        ? { username, password, captcha_id: captchaId, captcha_answer: captchaAnswer }
        : { username, email, password, captcha_id: captchaId, captcha_answer: captchaAnswer }

      const response = await fetch(`${API_BASE}${endpoint}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
      })

      const text = await response.text();
      if (!response.ok) {
        let errorMessage = mode === 'login' ? 'Login failed' : 'Registration failed';
        try {
          const errorData = JSON.parse(text);
          errorMessage = errorData.error || errorMessage;
        } catch (e) {
          errorMessage = text || errorMessage;
        }
        throw new Error(errorMessage)
      }

      const data: AuthResponse = JSON.parse(text);
      onSuccess(data)
    } catch (err: any) {
      setError(err.message || 'Authentication failed')
      fetchCaptcha() // Refresh captcha on error
    } finally {
      setLoading(false)
    }
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div className="space-y-2">
        <Label htmlFor="username">Username</Label>
        <Input
          id="username"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          placeholder="Enter username"
          required
        />
      </div>

      {mode === 'register' && (
        <div className="space-y-2">
          <Label htmlFor="email">Email</Label>
          <Input
            id="email"
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="Enter email"
            required
          />
        </div>
      )}

      <div className="space-y-2">
        <Label htmlFor="password">Password</Label>
        <div className="relative">
          <Input
            id="password"
            type={showPassword ? 'text' : 'password'}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="Enter password"
            required
          />
          <Button
            type="button"
            variant="ghost"
            size="icon"
            className="absolute right-0 top-0"
            onClick={() => setShowPassword(!showPassword)}
          >
            {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
          </Button>
        </div>
      </div>

      <div className="space-y-2">
        <Label>Captcha</Label>
        <div className="flex items-center gap-2">
          {captchaImage && (
            <img
              src={`data:image/png;base64,${captchaImage}`}
              alt="Captcha"
              className="h-12 rounded border border-slate-600"
            />
          )}
          <Button type="button" variant="outline" size="sm" onClick={fetchCaptcha}>
            Refresh
          </Button>
        </div>
        <Input
          value={captchaAnswer}
          onChange={(e) => setCaptchaAnswer(e.target.value)}
          placeholder="Enter captcha"
          required
        />
      </div>

      <Button type="submit" className="w-full" disabled={loading}>
        {loading ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : null}
        {mode === 'login' ? 'Login' : 'Register'}
      </Button>
    </form>
  )
}

// Encrypt Tab Component
function EncryptTab({ token, setError, setSuccess }: {
  token: string
  setError: (error: string | null) => void
  setSuccess: (success: string | null) => void
}) {
  const [text, setText] = useState('')
  const [seedWords, setSeedWords] = useState('')
  const [showSeed, setShowSeed] = useState(false)
  const [encryptedData, setEncryptedData] = useState('')
  const [loading, setLoading] = useState(false)
  const [copied, setCopied] = useState(false)

  const handleEncrypt = async () => {
    if (!text.trim() || !seedWords.trim()) {
      setError('Please enter both text and seed words')
      return
    }

    setLoading(true)
    setError(null)

    try {
      const response = await fetch(`${API_BASE}/encrypt`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ text, seed_words: seedWords })
      })

      const resText = await response.text();
      if (!response.ok) {
        let errorMessage = 'Encryption failed';
        try {
          const data = JSON.parse(resText);
          errorMessage = data.error || errorMessage;
        } catch (e) {
          errorMessage = resText || errorMessage;
        }
        throw new Error(errorMessage)
      }

      const data: EncryptResponse = JSON.parse(resText);
      setEncryptedData(data.encrypted_data)
      setSuccess('Text encrypted successfully!')
    } catch (err: any) {
      setError(err.message || 'Encryption failed')
    } finally {
      setLoading(false)
    }
  }

  const handleCopy = async () => {
    await navigator.clipboard.writeText(encryptedData)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <div className="grid gap-6 md:grid-cols-2">
      <Card className="bg-slate-800/50 border-slate-700">
        <CardHeader>
          <CardTitle className="text-white flex items-center gap-2">
            <Lock className="h-5 w-5 text-emerald-400" />
            Encrypt Text
          </CardTitle>
          <CardDescription>
            Encrypt your secret message using seed words as the key
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="text">Secret Text</Label>
            <Textarea
              id="text"
              value={text}
              onChange={(e) => setText(e.target.value)}
              placeholder="Enter your secret message..."
              rows={5}
              className="bg-slate-900 border-slate-600"
            />
            <p className="text-xs text-slate-500">{text.length} characters</p>
          </div>

          <div className="space-y-2">
            <Label htmlFor="seed">Seed Words / Passphrase</Label>
            <div className="relative">
              <Tooltip delayDuration={300}>
                <TooltipTrigger asChild>
                  <Input
                    id="seed"
                    type="text"
                    value={seedWords}
                    onChange={(e) => setSeedWords(e.target.value)}
                    placeholder="Enter your seed words..."
                    className={`bg-slate-900 border-slate-600 pr-10 ${!showSeed ? 'security-mask' : ''}`}
                    autoComplete="off"
                    data-1p-ignore
                  />
                </TooltipTrigger>
                <TooltipContent>
                  <p>Your secret key. Keep this safe!</p>
                </TooltipContent>
              </Tooltip>
              <Button
                type="button"
                variant="ghost"
                size="icon"
                className="absolute right-0 top-0 text-slate-400 hover:text-white"
                onClick={() => setShowSeed(!showSeed)}
              >
                {showSeed ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
              </Button>
            </div>
            <p className="text-xs text-slate-500">Remember this! You'll need it to decrypt</p>
          </div>

          <Tooltip delayDuration={300}>
            <TooltipTrigger asChild>
              <Button onClick={handleEncrypt} disabled={loading} className="w-full">
                {loading ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : <Lock className="h-4 w-4 mr-2" />}
                Encrypt
              </Button>
            </TooltipTrigger>
            <TooltipContent>
              <p>Lock your message with AES-256 encryption</p>
            </TooltipContent>
          </Tooltip>
        </CardContent>
      </Card>

      <Card className="bg-slate-800/50 border-slate-700">
        <CardHeader>
          <CardTitle className="text-white flex items-center gap-2">
            <Key className="h-5 w-5 text-emerald-400" />
            Encrypted Result
          </CardTitle>
          <CardDescription>Your encrypted data (Base64 encoded)</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <Textarea
            value={encryptedData}
            onChange={(e) => setEncryptedData(e.target.value)}
            placeholder="Encrypted data will appear here..."
            rows={10}
            className="bg-slate-900 border-slate-600 font-mono text-sm"
            readOnly
          />

          {encryptedData && (
            <div className="flex gap-2">
              <Button onClick={handleCopy} variant="outline" className="flex-1">
                {copied ? <Check className="h-4 w-4 mr-2" /> : <Copy className="h-4 w-4 mr-2" />}
                {copied ? 'Copied!' : 'Copy'}
              </Button>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}

// Decrypt Tab Component
function DecryptTab({ token, setError, setSuccess }: {
  token: string
  setError: (error: string | null) => void
  setSuccess: (success: string | null) => void
}) {
  const [encryptedData, setEncryptedData] = useState('')
  const [seedWords, setSeedWords] = useState('')
  const [showSeed, setShowSeed] = useState(false)
  const [decryptedText, setDecryptedText] = useState('')
  const [loading, setLoading] = useState(false)
  const [copied, setCopied] = useState(false)

  const handleDecrypt = async () => {
    if (!encryptedData.trim() || !seedWords.trim()) {
      setError('Please enter both encrypted data and seed words')
      return
    }

    setLoading(true)
    setError(null)

    try {
      const response = await fetch(`${API_BASE}/decrypt`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ encrypted_data: encryptedData, seed_words: seedWords })
      })

      const resText = await response.text();
      if (!response.ok) {
        let errorMessage = 'Decryption failed';
        try {
          const data = JSON.parse(resText);
          errorMessage = data.error || errorMessage;
        } catch (e) {
          errorMessage = resText || errorMessage;
        }
        throw new Error(errorMessage)
      }

      const data: DecryptResponse = JSON.parse(resText);
      setDecryptedText(data.decrypted_text)
      setSuccess('Text decrypted successfully!')
    } catch (err: any) {
      setError(err.message || 'Decryption failed')
    } finally {
      setLoading(false)
    }
  }

  const handleCopy = async () => {
    await navigator.clipboard.writeText(decryptedText)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <div className="grid gap-6 md:grid-cols-2">
      <Card className="bg-slate-800/50 border-slate-700">
        <CardHeader>
          <CardTitle className="text-white flex items-center gap-2">
            <Unlock className="h-5 w-5 text-emerald-400" />
            Decrypt Text
          </CardTitle>
          <CardDescription>
            Decrypt your secret message using the seed words
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="encrypted">Encrypted Data</Label>
            <Textarea
              id="encrypted"
              value={encryptedData}
              onChange={(e) => setEncryptedData(e.target.value)}
              placeholder="Paste your encrypted data..."
              rows={5}
              className="bg-slate-900 border-slate-600 font-mono text-sm"
            />
          </div>

          <div className="space-y-2">
            <Label htmlFor="seed">Seed Words / Passphrase</Label>
            <div className="relative">
              <Tooltip delayDuration={300}>
                <TooltipTrigger asChild>
                  <Input
                    id="seed"
                    type="text"
                    value={seedWords}
                    onChange={(e) => setSeedWords(e.target.value)}
                    placeholder="Enter your seed words..."
                    className={`bg-slate-900 border-slate-600 pr-10 ${!showSeed ? 'security-mask' : ''}`}
                    autoComplete="off"
                    data-1p-ignore
                  />
                </TooltipTrigger>
                <TooltipContent>
                  <p>Enter the exact key used to encrypt the message</p>
                </TooltipContent>
              </Tooltip>
              <Button
                type="button"
                variant="ghost"
                size="icon"
                className="absolute right-0 top-0 text-slate-400 hover:text-white"
                onClick={() => setShowSeed(!showSeed)}
              >
                {showSeed ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
              </Button>
            </div>
          </div>

          <Tooltip delayDuration={300}>
            <TooltipTrigger asChild>
              <Button onClick={handleDecrypt} disabled={loading} className="w-full">
                {loading ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : <Unlock className="h-4 w-4 mr-2" />}
                Decrypt
              </Button>
            </TooltipTrigger>
            <TooltipContent>
              <p>Unlock the original message</p>
            </TooltipContent>
          </Tooltip>
        </CardContent>
      </Card>

      <Card className="bg-slate-800/50 border-slate-700">
        <CardHeader>
          <CardTitle className="text-white flex items-center gap-2">
            <FileText className="h-5 w-5 text-emerald-400" />
            Decrypted Result
          </CardTitle>
          <CardDescription>Your original message</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <Textarea
            value={decryptedText}
            onChange={(e) => setDecryptedText(e.target.value)}
            placeholder="Decrypted text will appear here..."
            rows={10}
            className="bg-slate-900 border-slate-600"
            readOnly
          />

          {decryptedText && (
            <Button onClick={handleCopy} variant="outline" className="w-full">
              {copied ? <Check className="h-4 w-4 mr-2" /> : <Copy className="h-4 w-4 mr-2" />}
              {copied ? 'Copied!' : 'Copy'}
            </Button>
          )}
        </CardContent>
      </Card>
    </div>
  )
}

// Steganography Tab Component
function SteganoTab({ token, setError, setSuccess }: {
  token: string
  setError: (error: string | null) => void
  setSuccess: (success: string | null) => void
}) {
  const [mode, setMode] = useState<'embed' | 'extract'>('embed')
  const [embedType, setEmbedType] = useState<'text' | 'file'>('text')
  const [message, setMessage] = useState('')
  const [embedFile, setEmbedFile] = useState<{ name: string, type: string, data: string } | null>(null)
  const [seedWords, setSeedWords] = useState('')
  const [imageData, setImageData] = useState('')
  const [imagePreview, setImagePreview] = useState('')
  const [imageFormat, setImageFormat] = useState('png')
  const [resultImage, setResultImage] = useState('')
  const [extractedData, setExtractedData] = useState<{ type: 'text' | 'file', content: string, filename?: string, mime?: string } | null>(null)
  const [loading, setLoading] = useState(false)
  const [metadataUsed, setMetadataUsed] = useState(false)
  const [overflowSize, setOverflowSize] = useState(0)
  const [showSeed, setShowSeed] = useState(false)
  const [originalFilename, setOriginalFilename] = useState('')
  const [hasSteganoContent, setHasSteganoContent] = useState<boolean | null>(null)
  const [checkingStegano, setCheckingStegano] = useState(false)


  useEffect(() => {
    if (mode === 'extract' && imageData) {
      checkSteganoContent()
    } else {
      setHasSteganoContent(null)
    }
  }, [imageData, mode])

  const checkSteganoContent = async () => {
    if (!imageData) return

    setCheckingStegano(true)
    try {
      const response = await fetch(`${API_BASE}/stegano/detect`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
          image_data: imageData,
          image_format: imageFormat
        })
      })

      if (response.ok) {
        const data = await response.json()
        setHasSteganoContent(data.has_stegano)
      }
    } catch (e) {
      console.error('Failed to check stegano content', e)
    } finally {
      setCheckingStegano(false)
    }
  }

  const handleImageUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (file) {
      const reader = new FileReader()
      reader.onload = () => {
        setOriginalFilename(file.name)
        const base64 = reader.result as string
        setImagePreview(base64)
        // Extract just the data part
        const dataPart = base64.split(',')[1]
        setImageData(dataPart)

        // Detect format
        const ext = file.name.split('.').pop()?.toLowerCase()
        if (ext === 'jpg' || ext === 'jpeg') {
          setImageFormat('jpg')
        } else if (ext === 'webp') {
          setImageFormat('webp')
        } else {
          setImageFormat('png')
        }
      }
      reader.readAsDataURL(file)
    }
  }



  const handlePayloadFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (file) {
      const reader = new FileReader()
      reader.onload = () => {
        const base64 = reader.result as string
        // Keep full base64 string including data URI prefix for reconstruction? 
        // Or just data? For size efficiency, better just data, but need to reconstruct on download.
        // Let's store just the base64 data part to save space.
        const dataPart = base64.split(',')[1]
        setEmbedFile({
          name: file.name,
          type: file.type,
          data: dataPart
        })
      }
      reader.readAsDataURL(file)
    }
  }

  const handleEmbed = async () => {
    if (!imageData || !seedWords) {
      setError('Please provide image and seed words')
      return
    }

    if (embedType === 'text' && !message) {
      setError('Please enter a message')
      return
    }
    if (embedType === 'file' && !embedFile) {
      setError('Please select a file to embed')
      return
    }

    setLoading(true)
    setError(null)

    try {
      // Convert base64 to blob
      const byteCharacters = atob(imageData)
      const byteNumbers = new Array(byteCharacters.length)
      for (let i = 0; i < byteCharacters.length; i++) {
        byteNumbers[i] = byteCharacters.charCodeAt(i)
      }
      const byteArray = new Uint8Array(byteNumbers)
      const blob = new Blob([byteArray])



      // Prepare payload
      let finalMessage = ''
      if (embedType === 'text') {
        const payload = { t: 'text', c: message }
        finalMessage = JSON.stringify(payload)
      } else {
        const payload = {
          t: 'file',
          n: embedFile!.name,
          m: embedFile!.type,
          c: embedFile!.data
        }
        finalMessage = JSON.stringify(payload)
      }

      const formData = new FormData()
      formData.append('image', blob, `image.${imageFormat}`)
      formData.append('format', imageFormat)
      formData.append('message', finalMessage)
      formData.append('seed_words', seedWords)

      const response = await fetch(`${API_BASE}/stegano/embed`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`
        },
        body: formData
      })

      const resText = await response.text();
      if (!response.ok) {
        let errorMessage = 'Embedding failed';
        try {
          const data = JSON.parse(resText);
          errorMessage = data.error || errorMessage;
        } catch (e) {
          errorMessage = resText || errorMessage;
        }
        throw new Error(errorMessage)
      }

      const data: EmbedResponse = JSON.parse(resText);
      setResultImage(data.image_data)
      setMetadataUsed(data.metadata_used)
      setOverflowSize(data.overflow_size)
      setSuccess('Message embedded successfully!')
    } catch (err: any) {
      setError(err.message || 'Embedding failed')
    } finally {
      setLoading(false)
    }
  }

  const handleExtract = async () => {
    if (!imageData || !seedWords) {
      setError('Please provide image and seed words')
      return
    }

    setLoading(true)
    setError(null)

    try {
      const response = await fetch(`${API_BASE}/stegano/extract`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
          image_data: imageData,
          image_format: imageFormat,
          seed_words: seedWords
        })
      })

      const resText = await response.text();
      if (!response.ok) {
        let errorMessage = 'Extraction failed';
        try {
          const data = JSON.parse(resText);
          errorMessage = data.error || errorMessage;
        } catch (e) {
          errorMessage = resText || errorMessage;
        }
        throw new Error(errorMessage)
      }

      const data: ExtractResponse = JSON.parse(resText);

      // Try to parse as structured payload
      try {
        const payload = JSON.parse(data.message)
        if (payload.t === 'file') {
          setExtractedData({
            type: 'file',
            content: payload.c,
            filename: payload.n,
            mime: payload.m
          })
        } else if (payload.t === 'text') {
          setExtractedData({
            type: 'text',
            content: payload.c
          })
        } else {
          // Unrecognized JSON structure, treat as raw text
          setExtractedData({ type: 'text', content: data.message })
        }
      } catch (e) {
        // Not JSON, treat as raw text (backward compatibility)
        setExtractedData({ type: 'text', content: data.message })
      }

      setSuccess('Message extracted successfully!')
    } catch (err: any) {
      setError(err.message || 'Extraction failed')
    } finally {
      setLoading(false)
    }
  }

  const handleDownload = () => {
    const link = document.createElement('a')
    link.href = `data:image/${imageFormat};base64,${resultImage}`

    let downloadName = `stego-image.${imageFormat}`
    if (originalFilename) {
      const lastDotIndex = originalFilename.lastIndexOf('.')
      if (lastDotIndex !== -1) {
        const name = originalFilename.substring(0, lastDotIndex)
        // Use the original extension if possible, or fallback to imageFormat
        let ext = originalFilename.substring(lastDotIndex + 1).toLowerCase()
        // If image format changed (e.g. jpeg -> jpg), rely on the detected format for safety, 
        // but try to respect original if it matches the mime type group
        if (
          (ext === 'jpeg' && imageFormat === 'jpg') ||
          (ext === 'jpg' && imageFormat === 'jpg') ||
          (ext === 'png' && imageFormat === 'png') ||
          (ext === 'webp' && imageFormat === 'webp')
        ) {
          // Keep original extension (e.g. .jpeg)
        } else {
          ext = imageFormat
        }
        downloadName = `${name}_stegano.${ext}`
      } else {
        downloadName = `${originalFilename}_stegano.${imageFormat}`
      }
    }

    link.download = downloadName
    link.click()
  }

  return (
    <div className="space-y-6">
      <Tabs value={mode} onValueChange={(v) => setMode(v as 'embed' | 'extract')} className="w-full">
        <TabsList className="w-full flex bg-transparent p-0 border-b border-slate-700 rounded-none h-auto mb-6">
          <TabsTrigger
            value="embed"
            className="flex-1 rounded-none border-b-2 border-transparent data-[state=active]:border-emerald-400 data-[state=active]:bg-transparent data-[state=active]:shadow-none data-[state=active]:text-emerald-400 py-3 text-slate-400 hover:text-white transition-colors"
          >
            <Upload className="h-4 w-4 mr-2" />
            Embed Message
          </TabsTrigger>
          <TabsTrigger
            value="extract"
            className="flex-1 rounded-none border-b-2 border-transparent data-[state=active]:border-emerald-400 data-[state=active]:bg-transparent data-[state=active]:shadow-none data-[state=active]:text-emerald-400 py-3 text-slate-400 hover:text-white transition-colors"
          >
            <Download className="h-4 w-4 mr-2" />
            Extract Message
          </TabsTrigger>
        </TabsList>
      </Tabs>

      <div className="grid gap-6 md:grid-cols-2">
        <Card className="bg-slate-800/50 border-slate-700">
          <CardHeader>
            <CardTitle className="text-white flex items-center gap-2">
              <ImageIcon className="h-5 w-5 text-emerald-400" />
              {mode === 'embed' ? 'Source Image' : 'Steganographic Image'}
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <Label>Upload Image (PNG, JPG, WebP)</Label>
              <Input
                type="file"
                accept="image/png,image/jpeg,image/webp"
                onChange={handleImageUpload}
                className="bg-slate-900 border-slate-600"
              />
            </div>

            {imagePreview && (
              <div className="relative aspect-video rounded-lg overflow-hidden bg-slate-900">
                <img
                  src={imagePreview}
                  alt="Preview"
                  className="w-full h-full object-contain"
                />
              </div>
            )}

            {mode === 'extract' && imageData && (
              <div className="flex justify-center">
                {checkingStegano ? (
                  <Badge variant="outline" className="animate-pulse">
                    <Loader2 className="h-3 w-3 mr-1 animate-spin" />
                    Checking for hidden content...
                  </Badge>
                ) : (
                  hasSteganoContent === true ? (
                    <Badge className="bg-emerald-500/20 text-emerald-400 border-emerald-500/50">
                      <Check className="h-3 w-3 mr-1" />
                      Steganography Content Detected
                    </Badge>
                  ) : hasSteganoContent === false ? (
                    <Badge variant="outline" className="text-amber-500 border-amber-500/50">
                      <AlertCircle className="h-3 w-3 mr-1" />
                      No Hidden Content Detected
                    </Badge>
                  ) : null
                )}
              </div>
            )}

            <div className="space-y-2">
              <Label htmlFor="stegano-seed">Seed Words</Label>
              <div className="relative">
                <Tooltip delayDuration={300}>
                  <TooltipTrigger asChild>
                    <Input
                      id="stegano-seed"
                      type={showSeed ? 'text' : 'password'}
                      value={seedWords}
                      onChange={(e) => setSeedWords(e.target.value)}
                      placeholder="Enter seed words to encrypt/decrypt payload..."
                      className="bg-slate-900 border-slate-600 pr-10"
                    />
                  </TooltipTrigger>
                  <TooltipContent>
                    <p>Required to encrypt or decrypt the hidden content</p>
                  </TooltipContent>
                </Tooltip>
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  className="absolute right-0 top-0 h-full px-3 text-slate-400 hover:text-white"
                  onClick={() => setShowSeed(!showSeed)}
                >
                  {showSeed ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </Button>
              </div>
            </div>

            {mode === 'embed' && (
              <div className="space-y-4">
                <div className="space-y-2">
                  <Label>Content Type</Label>
                  <div className="flex gap-4">
                    <Button
                      variant={embedType === 'text' ? 'default' : 'outline'}
                      onClick={() => setEmbedType('text')}
                      size="sm"
                    >
                      <FileText className="h-4 w-4 mr-2" />
                      Text Message
                    </Button>
                    <Button
                      variant={embedType === 'file' ? 'default' : 'outline'}
                      onClick={() => setEmbedType('file')}
                      size="sm"
                    >
                      <Upload className="h-4 w-4 mr-2" />
                      Embed File
                    </Button>
                  </div>
                </div>

                {embedType === 'text' ? (
                  <div className="space-y-2">
                    <Label htmlFor="stegano-msg">Message to Hide</Label>
                    <Textarea
                      id="stegano-msg"
                      value={message}
                      onChange={(e) => setMessage(e.target.value)}
                      placeholder="Enter your secret message..."
                      rows={4}
                      className="bg-slate-900 border-slate-600"
                    />
                  </div>
                ) : (
                  <div className="space-y-2">
                    <Label>Select File to Hide</Label>
                    <Input
                      type="file"
                      onChange={handlePayloadFileUpload}
                      className="bg-slate-900 border-slate-600"
                    />
                    {embedFile && embedFile.data && (
                      <p className="text-xs text-emerald-400 mt-1">
                        Selected: {embedFile.name} ({(embedFile.data.length * 0.75 / 1024).toFixed(2)} KB approx)
                      </p>
                    )}
                    <p className="text-xs text-slate-500">
                      Note: Large files may require significant image capacity or metadata storage.
                    </p>
                  </div>
                )}
              </div>
            )}

            <Button
              onClick={mode === 'embed' ? handleEmbed : handleExtract}
              disabled={loading}
              className="w-full"
            >
              {loading ? (
                <Loader2 className="h-4 w-4 animate-spin mr-2" />
              ) : (
                mode === 'embed' ? <Upload className="h-4 w-4 mr-2" /> : <Download className="h-4 w-4 mr-2" />
              )}
              {mode === 'embed' ? 'Embed' : 'Extract'}
            </Button>
          </CardContent>
        </Card>

        <Card className="bg-slate-800/50 border-slate-700">
          <CardHeader>
            <CardTitle className="text-white flex items-center gap-2">
              {mode === 'embed' ? <Download className="h-5 w-5 text-emerald-400" /> : <FileText className="h-5 w-5 text-emerald-400" />}
              {mode === 'embed' ? 'Result Image' : 'Extracted Message'}
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            {mode === 'embed' ? (
              <>
                {resultImage && (
                  <>
                    <div className="relative aspect-video rounded-lg overflow-hidden bg-slate-900">
                      <img
                        src={`data:image/${imageFormat};base64,${resultImage}`}
                        alt="Steganographic"
                        className="w-full h-full object-contain"
                      />
                    </div>

                    {metadataUsed && (
                      <Alert className="bg-amber-500/10 border-amber-500">
                        <AlertCircle className="h-4 w-4 text-amber-500" />
                        <AlertDescription className="text-amber-500">
                          Metadata overflow used: {overflowSize} bytes stored in metadata
                        </AlertDescription>
                      </Alert>
                    )}

                    <Button onClick={handleDownload} className="w-full">
                      <Download className="h-4 w-4 mr-2" />
                      Download Image
                    </Button>
                  </>
                )}
              </>
            ) : (
              <>
                {extractedData ? (
                  extractedData.type === 'file' ? (
                    <div className="flex flex-col items-center justify-center p-6 border-2 border-dashed border-slate-700 rounded-lg text-center space-y-4">
                      <div className="h-16 w-16 bg-slate-800 rounded-full flex items-center justify-center">
                        <FileText className="h-8 w-8 text-emerald-400" />
                      </div>
                      <div>
                        <h3 className="text-lg font-medium text-white">{extractedData.filename}</h3>
                        <p className="text-sm text-slate-400">{(extractedData.content.length * 0.75 / 1024).toFixed(2)} KB</p>
                      </div>
                      <Button
                        onClick={() => {
                          const link = document.createElement('a');
                          link.href = `data:${extractedData.mime};base64,${extractedData.content}`;
                          link.download = extractedData.filename || 'extracted_file';
                          link.click();
                        }}
                        className="w-full"
                      >
                        <Download className="h-4 w-4 mr-2" />
                        Download Extracted File
                      </Button>
                    </div>
                  ) : (
                    <Textarea
                      value={extractedData.content}
                      placeholder="Extracted data..."
                      rows={10}
                      className="bg-slate-900 border-slate-600"
                      readOnly
                    />
                  )
                ) : (
                  <div className="flex items-center justify-center h-48 text-slate-500">
                    Extracted message will appear here...
                  </div>
                )}
              </>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  )
}

// QR Code Tab Component
function QRCodeTab({ token, setError, setSuccess }: {
  token: string
  setError: (error: string | null) => void
  setSuccess: (success: string | null) => void
}) {
  const [data, setData] = useState('')
  const [qrImage, setQrImage] = useState('')
  const [loading, setLoading] = useState(false)

  const handleGenerate = async () => {
    if (!data.trim()) {
      setError('Please enter data for QR code')
      return
    }

    setLoading(true)
    setError(null)

    try {
      const response = await fetch(`${API_BASE}/qrcode/generate`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ data, size: 300 })
      })

      const resText = await response.text();
      if (!response.ok) {
        let errorMessage = 'QR generation failed';
        try {
          const errorData = JSON.parse(resText);
          errorMessage = errorData.error || errorMessage;
        } catch (e) {
          errorMessage = resText || errorMessage;
        }
        throw new Error(errorMessage)
      }

      const result: QRCodeResponse = JSON.parse(resText);
      setQrImage(result.qr_image)
      setSuccess('QR code generated!')
    } catch (err: any) {
      setError(err.message || 'QR generation failed')
    } finally {
      setLoading(false)
    }
  }

  const handleDownload = () => {
    const link = document.createElement('a')
    link.href = `data:image/png;base64,${qrImage}`
    link.download = 'seed-words-qrcode.png'
    link.click()
  }

  return (
    <div className="grid gap-6 md:grid-cols-2">
      <Card className="bg-slate-800/50 border-slate-700">
        <CardHeader>
          <CardTitle className="text-white flex items-center gap-2">
            <QrCode className="h-5 w-5 text-emerald-400" />
            Generate QR Code
          </CardTitle>
          <CardDescription>
            Create a QR code for your seed words or passphrase
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="qr-data">Data (Seed Words)</Label>
            <Textarea
              id="qr-data"
              value={data}
              onChange={(e) => setData(e.target.value)}
              placeholder="Enter seed words or passphrase..."
              rows={4}
              className="bg-slate-900 border-slate-600"
            />
            <p className="text-xs text-slate-500">{data.length} characters (max 1000)</p>
          </div>

          <Button onClick={handleGenerate} disabled={loading} className="w-full">
            {loading ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : <QrCode className="h-4 w-4 mr-2" />}
            Generate QR Code
          </Button>
        </CardContent>
      </Card>

      <Card className="bg-slate-800/50 border-slate-700">
        <CardHeader>
          <CardTitle className="text-white">QR Code Result</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {qrImage ? (
            <>
              <div className="flex justify-center p-4 bg-white rounded-lg">
                <img
                  src={`data:image/png;base64,${qrImage}`}
                  alt="QR Code"
                  className="max-w-full"
                />
              </div>
              <Button onClick={handleDownload} className="w-full">
                <Download className="h-4 w-4 mr-2" />
                Download QR Code
              </Button>
            </>
          ) : (
            <div className="flex items-center justify-center h-48 text-slate-500">
              QR code will appear here
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}

// History Tab Component
function HistoryTab({ token, setError, setSuccess }: {
  token: string
  setError: (error: string | null) => void
  setSuccess: (success: string | null) => void
}) {
  const [messages, setMessages] = useState<Message[]>([])
  const [loading, setLoading] = useState(true)
  const [selectedMessage, setSelectedMessage] = useState<string | null>(null)
  const [decryptSeed, setDecryptSeed] = useState('')
  const [decryptedContent, setDecryptedContent] = useState('')
  const [showSeed, setShowSeed] = useState(false)

  useEffect(() => {
    fetchMessages()
  }, [token])

  const fetchMessages = async () => {
    try {
      const response = await fetch(`${API_BASE}/messages`, {
        headers: { 'Authorization': `Bearer ${token}` }
      })

      if (response.ok) {
        const data = await response.json()
        setMessages(data)
      }
    } catch (err) {
      setError('Failed to load messages')
    } finally {
      setLoading(false)
    }
  }

  const handleDelete = async (id: string) => {
    try {
      const response = await fetch(`${API_BASE}/messages/${id}`, {
        method: 'DELETE',
        headers: { 'Authorization': `Bearer ${token}` }
      })

      if (response.ok) {
        setMessages(messages.filter(m => m.id !== id))
        setSuccess('Message deleted')
      }
    } catch (err) {
      setError('Failed to delete message')
    }
  }

  const handleDecrypt = async (id: string) => {
    if (!decryptSeed) {
      setError('Please enter seed words')
      return
    }

    try {
      const response = await fetch(`${API_BASE}/messages/${id}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ seed_words: decryptSeed })
      })

      if (response.ok) {
        const data = await response.json()
        setDecryptedContent(data.decrypted_text)
        setSuccess('Message decrypted!')
      } else {
        const resText = await response.text();
        let errorMessage = 'Decryption failed';
        try {
          const data = JSON.parse(resText);
          errorMessage = data.error || errorMessage;
        } catch (e) {
          errorMessage = resText || errorMessage;
        }
        setError(errorMessage)
      }
    } catch (err) {
      setError('Decryption failed')
    }
  }

  const handleDownloadImage = async (id: string, originalFilename: string | null) => {
    try {
      const response = await fetch(`${API_BASE}/messages/${id}/image`, {
        headers: { 'Authorization': `Bearer ${token}` }
      })

      if (response.ok) {
        const blob = await response.blob()
        const url = window.URL.createObjectURL(blob)
        const link = document.createElement('a')
        link.href = url

        let filename = originalFilename || `stegano_image_${id}`
        // Ensure extension
        if (!filename.includes('.')) {
          const type = blob.type
          if (type === 'image/png') filename += '.png'
          else if (type === 'image/jpeg') filename += '.jpg'
          else if (type === 'image/webp') filename += '.webp'
        }

        link.download = filename
        document.body.appendChild(link)
        link.click()
        document.body.removeChild(link)
        window.URL.revokeObjectURL(url)
      } else {
        setError('Failed to download image')
      }
    } catch (err) {
      setError('Failed to download image')
    }
  }

  if (loading) {
    return (
      <div className="flex justify-center items-center h-64">
        <Loader2 className="h-8 w-8 animate-spin text-emerald-400" />
      </div>
    )
  }

  return (
    <div className="space-y-4">
      {messages.length === 0 ? (
        <Card className="bg-slate-800/50 border-slate-700">
          <CardContent className="flex flex-col items-center justify-center h-48 text-slate-500">
            <History className="h-12 w-12 mb-4" />
            <p>No encrypted messages yet</p>
          </CardContent>
        </Card>
      ) : (
        messages.map((msg) => (
          <Card key={msg.id} className="bg-slate-800/50 border-slate-700">
            <CardContent className="p-4">
              <div className="flex items-start justify-between">
                <div className="space-y-1">
                  <p className="text-sm text-slate-400">
                    {new Date(msg.created_at).toLocaleString()}
                  </p>
                  <div className="flex gap-2">
                    {msg.has_stegano && (
                      <Badge variant="secondary" className="bg-emerald-500/20 text-emerald-400">
                        <ImageIcon className="h-3 w-3 mr-1" />
                        Steganography
                      </Badge>
                    )}
                    {msg.original_filename && (
                      <Badge variant="outline" className="text-slate-400">
                        {msg.original_filename}
                      </Badge>
                    )}
                  </div>
                </div>
                <div className="flex gap-2">
                  {msg.has_stegano && (
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => handleDownloadImage(msg.id, msg.original_filename)}
                      title="Download Steganography Image"
                    >
                      <Download className="h-4 w-4 mr-1" />
                      Image
                    </Button>
                  )}
                  <Dialog>
                    <DialogTrigger asChild>
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => setSelectedMessage(msg.id)}
                      >
                        <Unlock className="h-4 w-4 mr-1" />
                        Decrypt
                      </Button>
                    </DialogTrigger>
                    <DialogContent>
                      <DialogHeader>
                        <DialogTitle>Decrypt Message</DialogTitle>
                        <DialogDescription>
                          Enter the seed words to decrypt this message
                        </DialogDescription>
                      </DialogHeader>
                      <div className="space-y-4">
                        <div className="relative">
                          <Input
                            type="text"
                            value={decryptSeed}
                            onChange={(e) => setDecryptSeed(e.target.value)}
                            placeholder="Enter seed words..."
                            className={`pr-10 ${!showSeed ? 'security-mask' : ''}`}
                            autoComplete="off"
                            data-1p-ignore
                          />
                          <Button
                            type="button"
                            variant="ghost"
                            size="icon"
                            className="absolute right-0 top-0 text-slate-400 hover:text-white"
                            onClick={() => setShowSeed(!showSeed)}
                          >
                            {showSeed ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                          </Button>
                        </div>
                        <Button onClick={() => handleDecrypt(msg.id)} className="w-full">
                          Decrypt
                        </Button>
                        {decryptedContent && (
                          <div className="space-y-2">
                            <Label>Decrypted Content</Label>
                            <Textarea
                              value={decryptedContent}
                              rows={5}
                              readOnly
                              className="bg-slate-900 border-slate-600"
                            />
                          </div>
                        )}
                      </div>
                    </DialogContent>
                  </Dialog>
                  <Button
                    size="sm"
                    variant="destructive"
                    onClick={() => handleDelete(msg.id)}
                  >
                    <Trash2 className="h-4 w-4" />
                  </Button>
                </div>
              </div>
            </CardContent>
          </Card>
        ))
      )}
    </div>
  )
}

// How to Use Dialog Component
function HowToUseDialog({ isMobile = false }: { isMobile?: boolean }) {
  return (
    <Dialog>
      <DialogTrigger asChild>
        <Button variant="ghost" size={isMobile ? 'default' : 'sm'} className={isMobile ? 'w-full justify-start' : ''}>
          <HelpCircle className="h-4 w-4 mr-2" />
          How to Use
        </Button>
      </DialogTrigger>
      <DialogContent className="max-w-2xl max-h-[80vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Shield className="h-6 w-6 text-emerald-400" />
            How to Use SteganoVault
          </DialogTitle>
          <DialogDescription>
            A comprehensive guide to securing your data.
          </DialogDescription>
        </DialogHeader>

        <Tabs defaultValue="basics" className="mt-4">
          <TabsList className="flex w-full bg-slate-800/50 p-1 rounded-lg">
            <TabsTrigger
              value="basics"
              className="flex-1 data-[state=active]:bg-emerald-500 data-[state=active]:text-white text-slate-400 hover:text-white"
            >
              Basics
            </TabsTrigger>
            <TabsTrigger
              value="stegano"
              className="flex-1 data-[state=active]:bg-emerald-500 data-[state=active]:text-white text-slate-400 hover:text-white"
            >
              Stegano
            </TabsTrigger>
            <TabsTrigger
              value="files"
              className="flex-1 data-[state=active]:bg-emerald-500 data-[state=active]:text-white text-slate-400 hover:text-white"
            >
              Files
            </TabsTrigger>
            <TabsTrigger
              value="qr"
              className="flex-1 data-[state=active]:bg-emerald-500 data-[state=active]:text-white text-slate-400 hover:text-white"
            >
              QR Code
            </TabsTrigger>
          </TabsList>

          <TabsContent value="basics" className="space-y-4 mt-4">
            <div className="space-y-2">
              <h3 className="font-semibold text-emerald-400">1. Encryption (Lock)</h3>
              <p className="text-sm text-slate-300">
                Use the <strong>Encrypt</strong> tab to secure plain text.
                You must provide a "Seed Words" (passphrase).
                The output is a text block that can only be read with that exact passphrase.
              </p>
            </div>
            <div className="space-y-2">
              <h3 className="font-semibold text-emerald-400">2. Decryption (Unlock)</h3>
              <p className="text-sm text-slate-300">
                Use the <strong>Decrypt</strong> tab to reveal the original message.
                Paste the encrypted text and enter the original seed words.
              </p>
            </div>
          </TabsContent>

          <TabsContent value="stegano" className="space-y-4 mt-4">
            <div className="space-y-2">
              <h3 className="font-semibold text-emerald-400">Hiding Data in Images</h3>
              <p className="text-sm text-slate-300">
                The <strong>Steganography</strong> tab allows you to embed secret messages (or files) inside regular images.
              </p>
              <ul className="list-disc pl-5 text-sm text-slate-300 space-y-1">
                <li><strong>Source Image:</strong> Upload a PNG, JPG, or WebP image.</li>
                <li><strong>Seed Words:</strong> Required to encrypt the payload before embedding.</li>
                <li><strong>Embedding:</strong> The app will generate a new image that looks identical to the original but contains your data.</li>
                <li><strong>Extracting:</strong> Upload the "Steganographic Image" and provide the seed words to retrieve your data.</li>
              </ul>
            </div>
          </TabsContent>

          <TabsContent value="files" className="space-y-4 mt-4">
            <div className="space-y-2">
              <h3 className="font-semibold text-emerald-400">Embedding Files</h3>
              <p className="text-sm text-slate-300">
                You can hide actual files (docs, small images, etc.) inside a cover image!
              </p>
              <ul className="list-disc pl-5 text-sm text-slate-300 space-y-1">
                <li>Select <strong>"Embed File"</strong> toggle in the Steganography tab.</li>
                <li>Choose a file to hide.</li>
                <li><strong>Note:</strong> File size matters! Hiding a large file requires a large cover image, or it will be stored in metadata (which can increase file size significantly).</li>
                <li>PNG images use LSB (Least Significant Bit) for invisible storage where possible.</li>
              </ul>
            </div>
          </TabsContent>

          <TabsContent value="qr" className="space-y-4 mt-4">
            <div className="space-y-2">
              <h3 className="font-semibold text-emerald-400">Sharing Secrets</h3>
              <p className="text-sm text-slate-300">
                The <strong>QR Code</strong> tab helps you share your Seed Words or small encrypted messages easily.
              </p>
              <ul className="list-disc pl-5 text-sm text-slate-300 space-y-1">
                <li>Type your text and generate a QR code.</li>
                <li>Download and share the image.</li>
                <li>Useful for physically transferring keys between devices.</li>
              </ul>
            </div>
          </TabsContent>
        </Tabs>
      </DialogContent>
    </Dialog>
  )
}

