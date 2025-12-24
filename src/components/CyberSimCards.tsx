import * as React from 'react';
import { Shield, AlertTriangle, CheckCircle, ChevronRight, User, Activity, Code, Terminal, Lock, Menu as MenuIcon, ArrowLeft, Clock, Mail } from 'lucide-react';

// Destructure hooks from the React namespace
const { useState, useEffect, useRef } = React;

// --- Types ---
type CardType = 'terminal' | 'injector' | 'social' | 'email';

interface CardData {
  id: number;
  title: string;
  type: CardType;
  difficulty: 'Easy' | 'Medium' | 'Hard';
  description: string;
  solution: string;
  explanation: string;
  simData: any;
  checkWin: (input: string) => boolean;
}

// --- Data: The Flashcard Deck ---
const cards: CardData[] = [
  // --- EXISTING CARDS ---
  {
    id: 1,
    title: 'SQL Injection (SQLi)',
    type: 'injector',
    difficulty: 'Easy',
    description: 'The login query is insecure. Trick the database into returning the admin user.',
    solution: "' OR '1'='1",
    explanation: "You successfully injected SQL code! By inputting `' OR '1'='1`, you changed the query structure. The database treated `OR '1'='1` as a valid condition (which is always true), returning the first record in the table: the Admin.",
    simData: {
      url: 'secure-bank.com/login',
      placeholder: 'Enter Password',
      mode: 'form'
    },
    checkWin: (input) => {
      const normalized = input.replace(/\s+/g, '').toLowerCase();
      return normalized.includes("'or'1'='1") || normalized.includes('"or"1"="1') || normalized.includes("'or1=1");
    }
  },
  {
    id: 2,
    title: 'Denial of Service (DoS)',
    type: 'terminal',
    difficulty: 'Medium',
    description: 'Target Server: 192.168.1.55. Overwhelm it with traffic.',
    solution: "ping -f 192.168.1.55",
    explanation: "The flood of ICMP packets overwhelmed the server's network stack. Legitimate traffic can no longer get through. This is a basic DoS. In a Distributed DoS (DDoS), this traffic would come from thousands of bots at once.",
    simData: {
      hostname: 'kali-linux:~#',
      targetIp: '192.168.1.55'
    },
    checkWin: (input) => {
      const cmd = input.trim().toLowerCase();
      return cmd.includes('ping') && (cmd.includes('-f') || cmd.includes('--flood')) && cmd.includes('192.168.1.55');
    }
  },
  {
    id: 3,
    title: 'Reflected XSS',
    type: 'injector',
    difficulty: 'Medium',
    description: 'This search page reflects input. Inject a script to trigger an alert.',
    solution: "<script>alert(1)</script>",
    explanation: "Because the website didn't 'sanitize' your input (remove special characters), the browser interpreted your text as code. This allows attackers to steal session cookies or redirect users to phishing sites.",
    simData: {
      url: 'shop-vulnerable.com/search',
      placeholder: 'Search products...',
      mode: 'form'
    },
    checkWin: (input) => {
      const normalized = input.replace(/\s+/g, '').toLowerCase();
      return normalized.includes('<script>alert(');
    }
  },
  {
    id: 4,
    title: 'Social Engineering',
    type: 'social',
    difficulty: 'Easy',
    description: 'Target: Bob (HR). Goal: Build trust, wait for the right moment, then trigger a panic to get his password.',
    solution: "Build rapport -> Wait -> Urgent Alert.",
    explanation: "Humans are often the weakest link in security. By establishing a baseline of trust and then creating sudden urgency ('account flagged'), you bypassed technical controls completely. Always verify identity before sharing credentials!",
    simData: {
      targetName: 'Bob (HR)',
      avatar: 'user'
    },
    checkWin: (input) => input === 'URGENT'
  },

  // --- NEW CARDS ---

  {
    id: 5,
    title: 'Broken Access (IDOR)',
    type: 'injector',
    difficulty: 'Easy',
    description: 'You are logged in as User 105. Modify the URL to access the CEO\'s profile (User 1).',
    solution: "Change id=105 to id=1",
    explanation: "Insecure Direct Object References (IDOR) occur when an app exposes a reference to an internal object (like a database ID) without checking access control. You simply requested ID 1, and the server gave it to you.",
    simData: {
      url: 'site.com/profile?id=',
      defaultUrlParam: '105',
      placeholder: '',
      mode: 'url' 
    },
    checkWin: (input) => input.trim() === '1'
  },
  {
    id: 6,
    title: 'OS Command Injection',
    type: 'injector',
    difficulty: 'Hard',
    description: 'This "Ping Tool" executes system commands. Append a command to read the password file.',
    solution: "8.8.8.8; cat /etc/passwd",
    explanation: "The application took your input and passed it directly to a system shell. By using the semicolon `;` separator, you chained a second command (`cat /etc/passwd`), forcing the server to reveal its sensitive user file.",
    simData: {
      url: 'net-tools.com/ping',
      placeholder: 'Enter IP address',
      mode: 'form'
    },
    checkWin: (input) => {
      const normalized = input.toLowerCase();
      return normalized.includes(';') && (normalized.includes('cat') || normalized.includes('etc/passwd'));
    }
  },
  {
    id: 7,
    title: 'Password Cracking',
    type: 'terminal',
    difficulty: 'Medium',
    description: 'You found a hash file. Use "John the Ripper" to brute force the password.',
    solution: "john --wordlist=rockyou.txt hash.txt",
    explanation: "Weak passwords can be cracked in seconds using dictionary attacks. Tools like John the Ripper compare the hash against millions of common passwords (like those in the 'rockyou' list) until a match is found.",
    simData: {
      hostname: 'kali-linux:~#',
      targetIp: 'File System'
    },
    checkWin: (input) => {
      const cmd = input.toLowerCase();
      return cmd.includes('john') && cmd.includes('rockyou');
    }
  },
  {
    id: 8,
    title: 'Ransomware (Phishing)',
    type: 'email',
    difficulty: 'Medium',
    description: 'You are an employee. You received this email. Simulate the victim\'s mistake to see the consequences.',
    solution: "Click the malicious link",
    explanation: "Ransomware often enters via phishing. One click on a malicious link downloaded a payload that encrypted your entire hard drive. The red screen is the 'Ransom Note' demanding payment for the decryption key.",
    simData: {
      sender: 'IT Support <support@company-update.site>',
      subject: 'URGENT: Security Patch Required',
      body: 'Dear User,\n\nYour workstation is missing a critical security update. Please install the patch immediately to avoid account suspension.\n\nClick below to update.'
    },
    checkWin: (input) => input === 'CLICKED_LINK'
  },
  {
    id: 9,
    title: 'Man-in-the-Middle',
    type: 'terminal',
    difficulty: 'Hard',
    description: 'Sniff the network traffic to capture unencrypted credentials.',
    solution: "tcpdump -i eth0",
    explanation: "Because the target was using HTTP instead of HTTPS, their traffic was unencrypted. By 'sniffing' the network packets, you were able to read their username and password in plain text as it traveled across the wire.",
    simData: {
      hostname: 'kali-linux:~#',
      targetIp: 'Network'
    },
    checkWin: (input) => input.toLowerCase().includes('tcpdump')
  }
];

// --- Components ---

const GuideBubble = ({ text }: { text: string }) => (
  <div className="absolute -top-14 left-0 z-10 animate-bounce pointer-events-none">
    <div className="bg-blue-600 text-white px-3 py-2 rounded-lg text-sm font-bold shadow-lg whitespace-nowrap border border-blue-400">
      Type: <span className="font-mono bg-black/20 px-1 rounded ml-1 text-yellow-300">{text}</span>
    </div>
    <div className="w-3 h-3 bg-blue-600 rotate-45 transform translate-x-4 -translate-y-1.5 border-r border-b border-blue-400"></div>
  </div>
);

const ConsequenceOverlay = ({ children, onNext }: { children: React.ReactNode, onNext: () => void }) => (
  <div className="absolute inset-0 bg-slate-900/95 z-50 flex flex-col items-center justify-center p-6 animate-fade-in text-center overflow-y-auto">
    <div className="mb-6 w-full max-w-md shrink-0">
      {children}
    </div>
    <button 
      onClick={onNext}
      className="bg-green-600 hover:bg-green-500 text-white px-6 py-2 rounded-full font-bold shadow-lg shadow-green-900/40 flex items-center gap-2 animate-bounce-subtle shrink-0"
    >
      Analyze Result <ChevronRight size={18} />
    </button>
  </div>
);

const TerminalSim = ({ card, onComplete }: { card: CardData; onComplete: () => void }) => {
  const [history, setHistory] = useState<string[]>(['Initializing interface...']);
  const [input, setInput] = useState('');
  const [phase, setPhase] = useState<'input' | 'consequence'>('input');
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [history]);

  const handleCommand = (e: React.FormEvent) => {
    e.preventDefault();
    const cmd = input.trim();
    if (!cmd) return;

    setHistory(prev => [...prev, `${card.simData.hostname} ${cmd}`]);

    if (cmd === 'help') {
      setHistory(prev => [...prev, 'Available commands: ping, nmap, help, clear, john, tcpdump']);
    } else if (cmd === 'clear') {
      setHistory([]);
    } else if (card.checkWin(cmd)) {
      if (card.id === 7) { 
          setHistory(prev => [...prev, `> Loaded 1 password hash...`, `> Press 'q' to quit`, `> Probing candidates...`]);
      } else if (card.id === 9) {
          setHistory(prev => [...prev, `> Listening on eth0...`, `> Capture size 262144 bytes`]);
      } else {
          setHistory(prev => [...prev, `> Executing...`]);
      }
      setTimeout(() => setPhase('consequence'), 1500);
    } else {
      setHistory(prev => [...prev, `> Command executed. No effect.`]);
    }
    setInput('');
  };

  return (
    <div className="relative h-[450px] flex flex-col">
       <div className="bg-slate-950 border-b border-green-900 p-2 text-xs font-mono text-green-600 flex justify-between">
          <span>TERM_SESSION: {phase === 'input' ? 'ACTIVE' : 'COMPLETE'}</span>
          <span>CTX: {card.simData.targetIp}</span>
       </div>

      <div className="bg-black border-x border-b border-green-900 rounded-b-lg p-4 font-mono text-sm flex-1 flex flex-col overflow-hidden">
        <div className="flex-1 overflow-y-auto space-y-1 mb-2 custom-scrollbar">
          {history.map((line, i) => (
            <div key={i} className="text-green-500">{line}</div>
          ))}
          <div ref={bottomRef} />
        </div>
        <form onSubmit={handleCommand} className="flex gap-2 relative">
          {phase === 'input' && <GuideBubble text={card.solution} />}
          <span className="text-green-400">{card.simData.hostname}</span>
          <input
            autoFocus
            value={input}
            onChange={(e) => setInput(e.target.value)}
            className="bg-transparent border-none outline-none text-green-300 flex-1 relative z-20"
            placeholder="Type command..."
            autoComplete="off"
            disabled={phase === 'consequence'}
          />
        </form>
      </div>

      {phase === 'consequence' && (
        <ConsequenceOverlay onNext={onComplete}>
          <div className="bg-black border border-green-500 rounded p-4 font-mono text-left mb-4 overflow-hidden">
             {card.id === 2 ? (
                <>
                    <div className="text-red-500 font-bold mb-2">SERVER STATUS: CRITICAL</div>
                    <div className="text-xs text-red-400">
                    [CRITICAL] CPU Load: 100%<br/>
                    [ALERT] Service UNREACHABLE
                    </div>
                </>
             ) : card.id === 7 ? (
                <>
                    <div className="text-green-500 mb-2">SESSION COMPLETE</div>
                    <div className="text-xs text-slate-300">
                    Loaded 143432 passwords...<br/>
                    Matching salt [user:admin]...<br/>
                    <span className="text-yellow-400 font-bold bg-slate-800 p-1 block mt-2">FOUND: 'princess123'</span>
                    </div>
                </>
             ) : card.id === 9 ? (
                <>
                    <div className="text-green-500 mb-2">PACKET CAPTURED</div>
                    <div className="text-xs text-slate-300">
                    SRC: 192.168.1.5:44382 &gt; DEST: 80<br/>
                    Protocol: HTTP (Cleartext)<br/>
                    <span className="text-yellow-400 font-bold bg-slate-800 p-1 block mt-2">Auth: admin:secret123</span>
                    </div>
                </>
             ) : (
                 <div className="text-green-500">Command Successful</div>
             )}
          </div>
          <p className="text-slate-300 text-sm">{card.id === 7 ? "Hash cracked successfully." : card.id === 9 ? "Credentials intercepted." : "Target crashed."}</p>
        </ConsequenceOverlay>
      )}
    </div>
  );
};

const InjectorSim = ({ card, onComplete }: { card: CardData; onComplete: () => void }) => {
  const [val, setVal] = useState(card.simData.defaultUrlParam || '');
  const [phase, setPhase] = useState<'input' | 'consequence'>('input');
  const [shaking, setShaking] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  const isUrlMode = card.simData.mode === 'url';
  
  // Reset state when card changes
  useEffect(() => {
    setVal(card.simData.defaultUrlParam || '');
    setPhase('input');
  }, [card]);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (card.checkWin(val)) {
      setPhase('consequence');
    } else {
      setShaking(true);
      setTimeout(() => setShaking(false), 500);
      if (!isUrlMode) setVal('');
    }
  };

  const handleContainerClick = () => {
    inputRef.current?.focus();
  };

  return (
    <div className="relative h-[450px] flex flex-col bg-gray-100 rounded-lg overflow-hidden border border-gray-300 shadow-md">
      
      {/* Live Hacker Vision */}
      <div className="bg-slate-800 text-slate-300 p-3 text-xs font-mono border-b border-slate-600">
        <div className="flex items-center gap-2 mb-1 text-blue-400 font-bold uppercase">
          <Code size={12} /> {card.id === 6 ? 'System Shell Preview' : 'Backend Query'}
        </div>
        <div className="bg-black/50 p-2 rounded text-gray-400 break-all h-16 overflow-y-auto">
          {card.id === 6 ? (
               <>
               $ ping -c 1 <span className="text-white font-bold">{val}</span>
               </>
          ) : isUrlMode ? (
               <>
               GET /profile?id=<span className="text-white font-bold">{val}</span> HTTP/1.1
               </>
          ) : card.title.includes('SQL') ? (
            <>
              SELECT * FROM users WHERE pass = '<span className="text-white font-bold">{val}</span>'
            </>
          ) : (
            <>
              &lt;div&gt;Results for: <span className="text-white font-bold">{val}</span>&lt;/div&gt;
            </>
          )}
        </div>
      </div>

      {/* Browser Bar */}
      <div className="bg-gray-200 px-3 py-2 flex items-center gap-2 border-b border-gray-300 relative z-20">
        <div className="flex gap-1">
          <div className="w-3 h-3 rounded-full bg-red-400"></div>
          <div className="w-3 h-3 rounded-full bg-yellow-400"></div>
          <div className="w-3 h-3 rounded-full bg-green-400"></div>
        </div>
        
        {isUrlMode ? (
            <div 
                className="flex-1 flex items-center border border-gray-300 rounded bg-white overflow-hidden relative cursor-text"
                onClick={handleContainerClick}
            >
                {/* Prefix */}
                <div className="bg-gray-50 px-3 py-1 text-xs text-gray-500 font-mono border-r border-gray-200 whitespace-nowrap select-none">
                    https://{card.simData.url}
                </div>
                {/* Flexible Input */}
                <form onSubmit={handleSubmit} className="flex-1 relative">
                    {phase === 'input' && <GuideBubble text={card.solution} />}
                    <input 
                        ref={inputRef}
                        value={val}
                        onChange={(e) => setVal(e.target.value)}
                        className={`w-full px-2 py-1 text-xs font-mono focus:outline-none text-black ${shaking ? 'bg-red-50' : 'bg-white'}`}
                        autoFocus
                    />
                </form>
            </div>
        ) : (
            <div className="bg-white flex-1 rounded px-2 text-xs text-gray-500 py-1 font-mono truncate">
            https://{card.simData.url}
            </div>
        )}
      </div>
      
      {/* Simulation Content */}
      <div className="flex-1 p-8 flex flex-col items-center justify-center bg-white relative">
        {isUrlMode ? (
             <div className="text-center text-gray-400">
                <User size={64} className="mx-auto mb-4 opacity-20"/>
                <p>Profile View: <span className="font-bold">User 105</span></p>
                <p className="text-xs mt-2">Try changing the URL above.</p>
             </div>
        ) : (
            <>
                <h3 className="text-gray-700 font-bold mb-4 text-lg">
                {card.title.includes('OS') ? 'Network Ping Tool' : card.title.includes('SQL') ? 'Secure Login' : 'Site Search'}
                </h3>
                <form onSubmit={handleSubmit} className={`w-full max-w-xs flex flex-col gap-3 ${shaking ? 'animate-shake' : ''} relative`}>
                <div className="relative">
                    {phase === 'input' && <GuideBubble text={card.solution} />}
                    <input 
                    value={val}
                    onChange={(e) => setVal(e.target.value)}
                    className="w-full border border-gray-300 rounded p-2 pl-3 text-black focus:outline-none focus:ring-2 focus:ring-blue-500 transition-all relative z-20"
                    placeholder={card.simData.placeholder}
                    type="text"
                    autoComplete="off"
                    />
                </div>
                <button type="submit" className="bg-blue-600 text-white py-2 rounded font-semibold hover:bg-blue-700 transition-colors z-20">
                    {card.title.includes('OS') ? 'Ping' : card.title.includes('SQL') ? 'Login' : 'Search'}
                </button>
                </form>
            </>
        )}
      </div>

      {phase === 'consequence' && (
        <ConsequenceOverlay onNext={onComplete}>
          {card.id === 6 ? (
            <div className="bg-black text-green-400 p-4 rounded text-left font-mono text-xs overflow-y-auto max-h-40">
                <div>&gt; PING 8.8.8.8 (8.8.8.8): 56 data bytes</div>
                <div>64 bytes from 8.8.8.8: icmp_seq=0 ttl=114 time=22.1 ms</div>
                <div className="text-yellow-300 mt-2">&gt; cat /etc/passwd</div>
                <div className="text-white">root:x:0:0:root:/root:/bin/bash</div>
                <div className="text-white">bin:x:1:1:bin:/bin:/sbin/nologin</div>
                <div className="text-white">admin:x:1000:1000:admin:/home/admin:/bin/bash</div>
            </div>
          ) : isUrlMode ? (
             <div className="bg-white border border-gray-200 p-4 rounded text-left shadow-lg w-full">
                 <div className="flex items-center gap-4 mb-4 border-b pb-4">
                     <div className="w-16 h-16 bg-gray-200 rounded-full flex items-center justify-center">
                         <User size={32} className="text-gray-500"/>
                     </div>
                     <div>
                         <div className="font-bold text-xl text-black">CEO Profile</div>
                         <div className="text-sm text-gray-500">ID: 1 (Admin)</div>
                     </div>
                 </div>
                 <div className="space-y-2">
                     <div className="flex justify-between text-sm"><span className="text-gray-600">Salary:</span> <span className="font-mono font-bold text-green-600">$1,500,000</span></div>
                     <div className="flex justify-between text-sm"><span className="text-gray-600">SSN:</span> <span className="font-mono font-bold text-red-600">***-**-1234</span></div>
                 </div>
             </div>
          ) : card.title.includes('SQL') ? (
            <div className="bg-white text-slate-900 rounded-lg shadow-xl overflow-hidden text-left text-xs font-mono border border-gray-300 w-full">
              <div className="bg-blue-600 text-white p-2 font-bold">Database Dump: users</div>
              <table className="w-full !text-black" style={{ color: '#000000' }}>
                <thead className="bg-gray-100 border-b">
                  <tr>
                    <th className="p-2 !text-black font-bold" style={{ color: '#000000' }}>ID</th>
                    <th className="p-2 !text-black font-bold" style={{ color: '#000000' }}>User</th>
                    <th className="p-2 !text-black font-bold" style={{ color: '#000000' }}>Role</th>
                  </tr>
                </thead>
                <tbody className="divide-y border-gray-200">
                  <tr className="bg-yellow-50 animate-pulse">
                    <td className="p-2 !text-black" style={{ color: '#000000' }}>1</td>
                    <td className="p-2 font-bold text-red-600">admin</td>
                    <td className="p-2 !text-black" style={{ color: '#000000' }}>superuser</td>
                  </tr>
                  <tr><td className="p-2 text-black" style={{ color: '#000000' }}>2</td><td className="p-2 text-black" style={{ color: '#000000' }}>user1</td><td className="p-2 text-black" style={{ color: '#000000' }}>guest</td></tr>
                  <tr><td className="p-2 text-black" style={{ color: '#000000' }}>3</td><td className="p-2 text-black" style={{ color: '#000000' }}>bob_hr</td><td className="p-2 text-black" style={{ color: '#000000' }}>staff</td></tr>
                </tbody>
              </table>
              <div className="p-2 bg-yellow-50 text-orange-700 border-t border-yellow-200 font-bold">
                ⚠ Query returned all rows because condition '1'='1' is TRUE.
              </div>
            </div>
          ) : (
            <div className="text-center">
              <div className="bg-white text-black p-4 rounded shadow-xl border border-gray-400 mb-4 transform scale-110">
                <div className="font-bold mb-2">Alert</div>
                <div className="flex items-center gap-2 justify-center text-lg">
                   <AlertTriangle className="text-yellow-500"/> 1
                </div>
                <button className="mt-4 bg-blue-500 text-white px-4 py-1 rounded text-sm">OK</button>
              </div>
              <div className="text-green-400 font-mono text-sm bg-black/50 p-2 rounded">
                 &lt;script&gt; executed successfully!
              </div>
            </div>
          )}
        </ConsequenceOverlay>
      )}
    </div>
  );
};

const EmailSim = ({ card, onComplete }: { card: CardData; onComplete: () => void }) => {
    const [phase, setPhase] = useState<'input' | 'consequence'>('input');
    
    const handleAction = () => {
        setPhase('consequence');
    };

    return (
        <div className="relative h-[500px] flex flex-col bg-white rounded-lg overflow-hidden border border-gray-300 shadow-md">
             {/* Fake Email Header */}
             <div className="bg-blue-600 p-3 text-white flex justify-between items-center">
                 <div className="flex items-center gap-2">
                     <Mail size={18} />
                     <span className="font-bold">Inbox (1)</span>
                 </div>
                 <div className="text-xs opacity-75">workmail.com</div>
             </div>

             {/* Email Content - Added overflow-y-auto here */}
             <div className="flex-1 p-6 text-gray-800 flex flex-col relative overflow-y-auto">
                <div className="border-b pb-4 mb-4">
                    <div className="font-bold text-lg mb-1">{card.simData.subject}</div>
                    <div className="flex items-center gap-2 text-sm text-gray-500">
                        <div className="w-8 h-8 bg-gray-200 rounded-full flex items-center justify-center font-bold text-gray-600">IT</div>
                        <div>
                            <span className="font-bold text-gray-900 block">IT Support</span>
                            <span className="text-xs text-red-500 font-mono">&lt;support@company-update.site&gt;</span>
                        </div>
                    </div>
                </div>
                
                <div className="text-sm leading-relaxed whitespace-pre-line mb-6">
                    {card.simData.body}
                </div>

                <div className="flex justify-center relative pb-6">
                    {phase === 'input' && (
                        <div className="absolute -top-10 animate-bounce">
                           <div className="bg-blue-600 text-white px-2 py-1 rounded text-xs font-bold">Click Here</div>
                           <div className="w-2 h-2 bg-blue-600 rotate-45 mx-auto -mt-1"></div>
                        </div>
                    )}
                    <button 
                        onClick={handleAction}
                        className="bg-red-600 hover:bg-red-700 text-white font-bold py-2 px-6 rounded shadow-lg transition-colors flex items-center gap-2"
                    >
                        <Shield size={16} /> Download Security Patch
                    </button>
                </div>
             </div>

             {phase === 'consequence' && (
                <ConsequenceOverlay onNext={onComplete}>
                   <div className="bg-red-600 p-6 rounded-lg shadow-2xl border-4 border-red-800 text-white text-center w-full max-w-sm mx-auto">
                       <Lock size={48} className="mx-auto mb-4 animate-bounce"/>
                       <h2 className="text-2xl font-extrabold mb-2 uppercase">Your Files Are Encrypted</h2>
                       <p className="text-sm opacity-90 mb-4">
                           A ransomware payload was executed on your machine.
                       </p>
                       <div className="bg-black/20 p-3 rounded font-mono text-xs text-left">
                           &gt; Encryption: AES-256<br/>
                           &gt; Status: LOCKED<br/>
                           &gt; Time remaining: 23:59:59
                       </div>
                   </div>
                </ConsequenceOverlay>
             )}
        </div>
    );
};

const SocialSim = ({ card, onComplete }: { card: CardData; onComplete: () => void }) => {
  const [phase, setPhase] = useState<'input' | 'consequence'>('input');
  const [trust, setTrust] = useState(20);
  const [messages, setMessages] = useState<{sender: string, text: string}[]>([
    { sender: 'Bob', text: 'Hey, did you need something? I am swamped.' }
  ]);
  const [processing, setProcessing] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    scrollRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  // Dynamic options based on trust level
  const getOptions = () => {
    if (trust < 40) {
        return [
            { id: 'RAPPORT', text: "Hey Bob! How's the project coming along?", impact: 20, response: "Oh hey! It's okay. Just stressful deadlines, you know?" },
            { id: 'DIRECT', text: "I need your credentials for a verify.", impact: -10, response: "Uh, I'm not supposed to give those out... who is this?" },
            { id: 'TECH', text: "Can you ping 127.0.0.1 for me?", impact: 0, response: "I'm not IT, sorry. I don't know how to do that." }
        ];
    } else if (trust < 80) {
        return [
             { id: 'WORK', text: "Did you see that memo about the bonus?", impact: 30, response: "Really? No I missed it. That would be amazing right now." },
             { id: 'JOKE', text: "Coffee machine is broken again...", impact: 10, response: "Tell me about it! I'm dying here." },
             { id: 'PUSH', text: "Just give me the password, Bob.", impact: -20, response: "Look, I need to get back to work." }
        ];
    } else if (trust < 100) {
        return [
            { id: 'WAIT', text: "[Action] Wait a few minutes...", impact: 30, response: "(Bob goes idle...)" },
            { id: 'CHAT', text: "Any plans for the weekend?", impact: 5, response: "Probably just sleeping honestly." }
        ]
    } else {
        return [
            { id: 'ATTACK', text: "SEND URGENT ALERT: Account Flagged for Suspicious Activity", impact: 0, response: "" } // Win condition
        ]
    }
  };

  const handleChoice = (opt: any) => {
    setMessages(prev => [...prev, { sender: 'You', text: opt.text }]);
    setProcessing(true);
    
    setTimeout(() => {
      if (opt.id === 'ATTACK') {
        // Final win condition
        if (card.checkWin('URGENT')) {
           setPhase('consequence');
        }
      } else {
         // Normal turn
         const newTrust = Math.min(100, Math.max(0, trust + opt.impact));
         setTrust(newTrust);
         
         let reply = opt.response;
         if (opt.id === 'WAIT') {
             reply = "Bob (Status): Away - 15 mins";
         }
         setMessages(prev => [...prev, { sender: 'Bob', text: reply }]);
      }
      setProcessing(false);
    }, 1000);
  };

  const currentOptions = getOptions();

  return (
    <div className="relative h-[500px] flex flex-col bg-white rounded-lg shadow-md border border-gray-200 overflow-hidden">
       {/* Trust Meter */}
       <div className="bg-slate-800 text-slate-300 p-3 text-xs font-mono border-b border-slate-600 flex flex-col gap-2">
         <div className="flex justify-between items-center">
            <span>TARGET_TRUST_LEVEL</span>
            <span className={`font-bold ${trust >= 80 ? 'text-green-400' : trust >= 40 ? 'text-yellow-400' : 'text-red-400'}`}>
              {trust}%
            </span>
         </div>
         <div className="w-full bg-slate-700 h-2 rounded-full overflow-hidden">
            <div 
                className={`h-full transition-all duration-500 ${trust >= 80 ? 'bg-green-500' : trust >= 40 ? 'bg-yellow-500' : 'bg-red-500'}`}
                style={{ width: `${trust}%` }}
            ></div>
         </div>
       </div>

      <div className="bg-blue-600 text-white p-3 flex items-center gap-2 shadow-sm z-10">
        <div className="bg-white/20 p-1 rounded-full"><User size={16}/></div>
        <span className="font-semibold">Chat with {card.simData.targetName}</span>
      </div>

      <div className="flex-1 p-4 bg-gray-50 space-y-3 overflow-y-auto custom-scrollbar">
        {messages.map((m, i) => (
          <div key={i} className={`flex ${m.sender === 'You' ? 'justify-end' : 'justify-start'} animate-fade-in-up`}>
            <div className={`max-w-[85%] p-3 rounded-2xl text-sm shadow-sm 
                ${m.sender === 'You' 
                    ? 'bg-blue-500 text-white rounded-br-none' 
                    : m.text.includes('Status') 
                        ? 'bg-slate-200 text-slate-600 font-mono italic text-xs'
                        : 'bg-white text-gray-800 rounded-bl-none border border-gray-200'
                }`}>
              {m.text}
            </div>
          </div>
        ))}
        {processing && (
             <div className="flex justify-start animate-pulse">
                <div className="bg-gray-200 p-2 rounded-2xl rounded-bl-none text-gray-500 text-xs flex items-center gap-1">
                    <span>typing</span><span className="animate-bounce">.</span><span className="animate-bounce delay-100">.</span><span className="animate-bounce delay-200">.</span>
                </div>
             </div>
        )}
        <div ref={scrollRef} />
      </div>

      <div className="p-3 bg-gray-100 border-t border-gray-200 grid grid-cols-1 gap-2 relative z-20">
        {currentOptions.map((opt, idx) => (
          <div key={idx} className="relative">
             {/* Guide arrow logic */}
             {phase === 'input' && !processing && (
                 (trust < 40 && opt.id === 'RAPPORT') ||
                 (trust >= 40 && trust < 80 && opt.id === 'WORK') ||
                 (trust >= 80 && trust < 100 && opt.id === 'WAIT') ||
                 (trust >= 100 && opt.id === 'ATTACK')
             ) && (
               <div className="absolute right-2 -top-3 z-30 animate-bounce">
                   <div className="bg-blue-600 text-white text-[10px] px-2 py-0.5 rounded shadow border border-blue-400 font-bold">
                       Best Choice
                   </div>
               </div>
             )}
             
             <button 
              onClick={() => handleChoice(opt)}
              disabled={phase === 'consequence' || processing}
              className={`w-full text-sm text-left p-3 rounded-lg border transition-all duration-200 font-medium
                ${opt.id === 'ATTACK' 
                    ? 'bg-red-50 border-red-300 text-red-700 hover:bg-red-100 hover:border-red-500 font-bold' 
                    : opt.id === 'WAIT'
                        ? 'bg-purple-50 border-purple-300 text-purple-700 hover:bg-purple-100'
                        : 'bg-white border-gray-300 text-gray-700 hover:bg-blue-50 hover:border-blue-300 hover:text-blue-800'
                }
                hover:shadow-md hover:-translate-y-0.5 disabled:opacity-50 disabled:cursor-not-allowed disabled:transform-none
              `}
            >
              <div className="flex items-center gap-2">
                  {opt.id === 'WAIT' && <Clock size={16} />}
                  {opt.id === 'ATTACK' && <AlertTriangle size={16} />}
                  {opt.text}
              </div>
            </button>
          </div>
        ))}
      </div>

       {phase === 'consequence' && (
         <ConsequenceOverlay onNext={onComplete}>
           <div className="bg-gray-100 p-4 rounded-lg text-left border border-gray-300 mb-2">
             <div className="text-xs text-gray-500 mb-1">Bob (HR) • Now</div>
             <div className="text-gray-800 text-sm">
               Oh shoot! Is that why my screen flickered? I didn't realize it was so serious. My password is <span className="bg-yellow-200 font-mono px-1 font-bold text-red-600">Hunter2!</span>. Please fix it ASAP!
             </div>
           </div>
           <div className="text-red-400 text-sm font-mono mt-2">
             [!] CREDENTIALS COMPROMISED
           </div>
         </ConsequenceOverlay>
       )}
    </div>
  );
};

const MenuScreen = ({ cards, onSelect }: { cards: CardData[], onSelect: (card: CardData) => void }) => {
  return (
    <div className="w-full max-w-4xl p-6">
      <div className="text-center mb-10">
        <h1 className="text-4xl font-bold text-white mb-2">Select Target</h1>
        <p className="text-slate-400">Choose a simulation to exploit</p>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {cards.map((c) => (
          <button 
            key={c.id} 
            onClick={() => onSelect(c)}
            className="group bg-slate-800 hover:bg-slate-700 border border-slate-700 hover:border-green-500/50 p-6 rounded-xl transition-all text-left flex items-start gap-4 relative overflow-hidden"
          >
            <div className={`p-3 rounded-lg ${
              c.type === 'terminal' ? 'bg-blue-500/10 text-blue-400' :
              c.type === 'injector' ? 'bg-purple-500/10 text-purple-400' :
              c.type === 'email' ? 'bg-red-500/10 text-red-400' :
              'bg-orange-500/10 text-orange-400'
            }`}>
              {c.type === 'terminal' && <Terminal size={24} />}
              {c.type === 'injector' && <Code size={24} />}
              {c.type === 'social' && <User size={24} />}
              {c.type === 'email' && <Mail size={24} />}
            </div>
            <div className="flex-1">
              <div className="flex justify-between items-start mb-2">
                 <h3 className="text-lg font-bold text-white group-hover:text-green-400 transition-colors">{c.title}</h3>
                 <span className={`text-xs px-2 py-1 rounded font-bold uppercase tracking-wider ${
                    c.difficulty === 'Easy' ? 'bg-green-500/20 text-green-400' : 
                    c.difficulty === 'Medium' ? 'bg-yellow-500/20 text-yellow-400' : 'bg-red-500/20 text-red-400'
                 }`}>
                   {c.difficulty}
                 </span>
              </div>
              <p className="text-slate-400 text-sm line-clamp-2">{c.description}</p>
            </div>
            <div className="absolute bottom-0 left-0 w-full h-1 bg-gradient-to-r from-transparent via-green-500/0 to-transparent group-hover:via-green-500/50 transition-all"></div>
          </button>
        ))}
      </div>
    </div>
  );
};

// --- Main App Component ---

export default function CyberSimCards() {
  const [activeCard, setActiveCard] = useState<CardData | null>(null);
  const [flipped, setFlipped] = useState(false);
  const [isSimulating, setIsSimulating] = useState(true);

  // When card is selected from menu
  const handleSelectCard = (card: CardData) => {
    setActiveCard(card);
    setFlipped(false);
    setIsSimulating(true);
  };

  const handleNextPhase = () => {
    setIsSimulating(false);
    setFlipped(true);
  };

  const returnToMenu = () => {
    setActiveCard(null);
  };

  if (!activeCard) {
    return (
      <div className="min-h-screen bg-slate-900 text-slate-200 font-sans flex flex-col items-center py-8 px-4">
        {/* Header */}
        <div className="w-full max-w-4xl mb-8 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-green-500/10 rounded-lg border border-green-500/30">
              <Shield className="text-green-500" size={28} />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-white tracking-tight">CyberSim <span className="text-green-500">Flashcards</span></h1>
              <p className="text-slate-400 text-sm">Interactive Attack Simulations</p>
            </div>
          </div>
        </div>
        <MenuScreen cards={cards} onSelect={handleSelectCard} />
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-slate-900 text-slate-200 font-sans flex flex-col items-center py-8 px-4">
      {/* Simulation Header */}
      <div className="w-full max-w-2xl mb-8 flex items-center justify-between">
        <button 
          onClick={returnToMenu}
          className="flex items-center gap-2 text-slate-400 hover:text-white transition-colors group"
        >
          <div className="p-2 bg-slate-800 rounded-lg group-hover:bg-slate-700">
             <ArrowLeft size={20} />
          </div>
          <span className="font-semibold">Back to Menu</span>
        </button>
        <div className="text-right">
          <div className="text-sm text-slate-400">Active Simulation</div>
          <div className="text-xl font-mono text-green-400 font-bold">
            {activeCard.title}
          </div>
        </div>
      </div>

      {/* Main Card Area */}
      <div className="w-full max-w-2xl perspective-1000 min-h-[500px] relative">
        
        {/* Card Container */}
        <div className={`relative w-full transition-all duration-500 transform-style-3d ${!isSimulating ? 'rotate-y-0' : ''}`}>
          
          {/* FRONT FACE (Simulation) */}
          {isSimulating && (
            <div className="w-full bg-slate-800 rounded-xl shadow-2xl border border-slate-700 overflow-hidden animate-fade-in-up">
              {/* Card Header */}
              <div className="bg-slate-900/50 p-4 border-b border-slate-700 flex justify-between items-center">
                <div className="flex items-center gap-2">
                  <span className={`px-2 py-0.5 rounded text-xs font-bold uppercase tracking-wider
                    ${activeCard.difficulty === 'Easy' ? 'bg-green-500/20 text-green-400' : 
                      activeCard.difficulty === 'Medium' ? 'bg-yellow-500/20 text-yellow-400' : 'bg-red-500/20 text-red-400'}`}>
                    {activeCard.difficulty}
                  </span>
                  <span className="text-slate-400 text-xs uppercase tracking-widest">{activeCard.type}</span>
                </div>
              </div>

              {/* Challenge Description */}
              <div className="p-6">
                <h2 className="text-2xl font-bold text-white mb-2">{activeCard.title}</h2>
                <p className="text-slate-300 mb-6 leading-relaxed">{activeCard.description}</p>

                {/* The Interactive Module */}
                <div className="mt-4 mb-2">
                   {activeCard.type === 'terminal' && <TerminalSim key={activeCard.id} card={activeCard} onComplete={handleNextPhase} />}
                   {activeCard.type === 'injector' && <InjectorSim key={activeCard.id} card={activeCard} onComplete={handleNextPhase} />}
                   {activeCard.type === 'social' && <SocialSim key={activeCard.id} card={activeCard} onComplete={handleNextPhase} />}
                   {activeCard.type === 'email' && <EmailSim key={activeCard.id} card={activeCard} onComplete={handleNextPhase} />}
                </div>
              </div>
              
              <div className="bg-slate-900/30 p-3 text-center text-xs text-slate-500 border-t border-slate-700">
                {activeCard.type === 'email' ? 'Follow the instructions above' : 'Type the command shown in the blue bubble to proceed'}
              </div>
            </div>
          )}

          {/* BACK FACE (Explanation) */}
          {!isSimulating && (
            <div className="w-full bg-slate-800 rounded-xl shadow-[0_0_30px_rgba(0,255,0,0.1)] border border-green-500/30 overflow-hidden animate-flip-in">
              <div className="bg-green-900/20 p-4 border-b border-green-500/30 flex justify-between items-center">
                <div className="flex items-center gap-2 text-green-400 font-bold">
                  <CheckCircle size={20} />
                  <span>ATTACK ANALYZED</span>
                </div>
                <button 
                  onClick={returnToMenu}
                  className="flex items-center gap-1 text-xs text-green-400 hover:text-green-300 transition-colors"
                >
                  RETURN TO MENU <MenuIcon size={14} />
                </button>
              </div>

              <div className="p-8">
                <h2 className="text-3xl font-bold text-white mb-4">{activeCard.title}</h2>
                
                <div className="bg-slate-900/50 rounded-lg p-5 border-l-4 border-green-500 mb-6">
                  <h3 className="text-sm font-semibold text-green-400 uppercase tracking-widest mb-2">What just happened?</h3>
                  <p className="text-slate-300 leading-relaxed">
                    {activeCard.explanation}
                  </p>
                </div>

                <div className="grid grid-cols-2 gap-4">
                  <div className="bg-slate-700/30 p-4 rounded border border-slate-700">
                    <div className="text-xs text-slate-500 uppercase mb-1">Defense Strategy</div>
                    <div className="text-sm text-slate-200">
                      {activeCard.id === 1 && "Use Prepared Statements (Parameterized Queries)."}
                      {activeCard.id === 2 && "Implement Rate Limiting, Firewalls, and CDNs."}
                      {activeCard.id === 3 && "Sanitize Inputs and use Content Security Policy (CSP)."}
                      {activeCard.id === 4 && "Employee Awareness Training & 2FA."}
                      {activeCard.id === 5 && "Implement Proper Access Controls (Check user permissions)."}
                      {activeCard.id === 6 && "Validate/Sanitize input and avoid running system commands."}
                      {activeCard.id === 7 && "Use Strong, Unique Passwords and Salted Hashes."}
                      {activeCard.id === 8 && "Email Filters, Sandbox Attachments, and User Training."}
                      {activeCard.id === 9 && "Always use HTTPS/TLS to encrypt traffic."}
                    </div>
                  </div>
                   <div className="bg-slate-700/30 p-4 rounded border border-slate-700">
                    <div className="text-xs text-slate-500 uppercase mb-1">Impact Level</div>
                    <div className="text-sm text-red-400 font-bold">CRITICAL</div>
                  </div>
                </div>

              </div>
              
              <div className="p-4 flex justify-center bg-slate-900/30 border-t border-slate-700">
                 <button 
                  onClick={returnToMenu}
                  className="bg-green-600 hover:bg-green-500 text-white px-8 py-2 rounded font-bold shadow-lg shadow-green-900/20 transition-all flex items-center gap-2"
                 >
                   Return to Menu <MenuIcon size={18}/>
                 </button>
              </div>
            </div>
          )}
        </div>
      </div>
      <style>{`
        .animate-shake {
          animation: shake 0.5s cubic-bezier(.36,.07,.19,.97) both;
        }
        @keyframes shake {
          10%, 90% { transform: translate3d(-1px, 0, 0); }
          20%, 80% { transform: translate3d(2px, 0, 0); }
          30%, 50%, 70% { transform: translate3d(-4px, 0, 0); }
          40%, 60% { transform: translate3d(4px, 0, 0); }
        }
        .animate-bounce-subtle {
          animation: bounce-subtle 2s infinite;
        }
        @keyframes bounce-subtle {
          0%, 100% { transform: translateY(-3%); }
          50% { transform: translateY(3%); }
        }
      `}</style>
    </div>
  );
}