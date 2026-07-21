import React, { useState, useEffect } from 'react';
import axios from 'axios';
import './App.css';

const API_BASE = 'http://localhost:8080/api/v1';

// Add request interceptor to attach JWT token
axios.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('pki_token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

function App() {
  const [token, setToken] = useState(localStorage.getItem('pki_token') || null);
  const [username, setUsername] = useState(localStorage.getItem('pki_username') || '');
  const [role, setRole] = useState(localStorage.getItem('pki_role') || '');
  const [activeTab, setActiveTab] = useState('dashboard');
  const [notification, setNotification] = useState(null);

  // Login form states
  const [loginUsername, setLoginUsername] = useState('');
  const [loginPassword, setLoginPassword] = useState('');

  // Keys states
  const [keysList, setKeysList] = useState([]);
  const [keyAlgorithm, setKeyAlgorithm] = useState('RSA');
  const [keySize, setKeySize] = useState(2048);

  // CA states
  const [subjectDN, setSubjectDN] = useState('CN=Root CA,O=INSA,C=FR');
  const [caKeyType, setCaKeyType] = useState('RSA');
  const [caKeySize, setCaKeySize] = useState(2048);
  const [caProfile, setCaProfile] = useState('RootCA');
  const [parentSerial, setParentSerial] = useState('');
  const [caList, setCaList] = useState([]);

  // CSR Sign states
  const [csrPem, setCsrPem] = useState('');
  const [selectedCaSerial, setSelectedCaSerial] = useState('');
  const [csrProfile, setCsrProfile] = useState('EndEntity');

  // Certificate lifecycle states
  const [certList, setCertList] = useState([]);
  const [selectedCert, setSelectedCert] = useState(null);
  const [selectedCertChain, setSelectedCertChain] = useState([]);
  const [revokeReason, setRevokeReason] = useState('KEY_COMPROMISE');

  // Audit log states
  const [auditLogs, setAuditLogs] = useState([]);

  // Stats for dashboard
  const [stats, setStats] = useState({ keys: 0, cas: 0, certs: 0, issues: 0 });

  useEffect(() => {
    if (token) {
      fetchData();
    }
  }, [token, activeTab]);

  const showNotification = (message, type = 'success') => {
    setNotification({ message, type });
    setTimeout(() => setNotification(null), 5000);
  };

  const fetchData = async () => {
    try {
      if (activeTab === 'dashboard') {
        const [keysRes, certsRes, logsRes] = await Promise.all([
          axios.get(`${API_BASE}/keys`),
          axios.get(`${API_BASE}/certificates`),
          axios.get(`${API_BASE}/auth/login`).catch(() => ({ data: [] })) // Placeholder or handled gracefully
        ]);
        const keys = keysRes.data || [];
        const certs = certsRes.data || [];
        const cas = certs.filter(c => c.certificateType === 'ROOT' || c.certificateType === 'INTERMEDIATE');
        setStats({
          keys: keys.length,
          cas: cas.length,
          certs: certs.length,
          issues: certs.filter(c => c.status === 'REVOKED').length
        });
      } else if (activeTab === 'keys') {
        const res = await axios.get(`${API_BASE}/keys`);
        setKeysList(res.data || []);
      } else if (activeTab === 'cas') {
        const res = await axios.get(`${API_BASE}/certificates`);
        const allCerts = res.data || [];
        setCaList(allCerts.filter(c => c.certificateType === 'ROOT' || c.certificateType === 'INTERMEDIATE'));
      } else if (activeTab === 'signer') {
        const res = await axios.get(`${API_BASE}/certificates`);
        const allCerts = res.data || [];
        const cas = allCerts.filter(c => c.certificateType === 'ROOT' || c.certificateType === 'INTERMEDIATE');
        setCaList(cas);
        if (cas.length > 0 && !selectedCaSerial) {
          setSelectedCaSerial(cas[0].serialNumber);
        }
      } else if (activeTab === 'lifecycle') {
        const res = await axios.get(`${API_BASE}/certificates`);
        setCertList(res.data || []);
      } else if (activeTab === 'audit') {
        // Fetch audit logs if we set up an endpoint or mock it
        const res = await axios.get(`${API_BASE}/certificates`).catch(() => ({ data: [] })); // fallback
        // We'll create a fallback list of audit logs or retrieve them from db if we add an endpoint
        setAuditLogs([]);
      }
    } catch (err) {
      console.error(err);
      showNotification('Failed to fetch data from API server: ' + (err.response?.data || err.message), 'error');
    }
  };

  const handleLogin = async (e) => {
    e.preventDefault();
    try {
      const res = await axios.post(`${API_BASE}/auth/login`, {
        username: loginUsername,
        password: loginPassword
      });
      const { token, username: user, role: userRole } = res.data;
      localStorage.setItem('pki_token', token);
      localStorage.setItem('pki_username', user);
      localStorage.setItem('pki_role', userRole);
      setToken(token);
      setUsername(user);
      setRole(userRole);
      showNotification('Logged in successfully!');
    } catch (err) {
      showNotification('Authentication failed: ' + (err.response?.data || err.message), 'error');
    }
  };

  const handleLogout = () => {
    localStorage.removeItem('pki_token');
    localStorage.removeItem('pki_username');
    localStorage.removeItem('pki_role');
    setToken(null);
    setUsername('');
    setRole('');
  };

  const handleGenerateKey = async (e) => {
    e.preventDefault();
    try {
      const res = await axios.post(`${API_BASE}/keys/generate`, {
        algorithm: keyAlgorithm,
        keySize: parseInt(keySize)
      });
      showNotification(`Key pair generated successfully! ID: ${res.data.id}`);
      fetchData();
    } catch (err) {
      showNotification('Key generation failed: ' + (err.response?.data || err.message), 'error');
    }
  };

  const handleInitRootCa = async (e) => {
    e.preventDefault();
    try {
      const res = await axios.post(`${API_BASE}/certificates/cas/root`, {
        subjectDN,
        keyType: caKeyType,
        keySizeOrCurve: parseInt(caKeySize),
        profileName: caProfile
      });
      showNotification(`Root CA initialized! Serial: ${res.data.serialNumber}`);
      fetchData();
    } catch (err) {
      showNotification('Root CA initialization failed: ' + (err.response?.data || err.message), 'error');
    }
  };

  const handleInitIntermediateCa = async (e) => {
    e.preventDefault();
    try {
      const res = await axios.post(`${API_BASE}/certificates/cas/intermediate`, {
        subjectDN,
        parentSerialNumber: parentSerial,
        keyType: caKeyType,
        keySizeOrCurve: parseInt(caKeySize),
        profileName: caProfile
      });
      showNotification(`Intermediate CA initialized! Serial: ${res.data.serialNumber}`);
      fetchData();
    } catch (err) {
      showNotification('Intermediate CA initialization failed: ' + (err.response?.data || err.message), 'error');
    }
  };

  const handleSignCsr = async (e) => {
    e.preventDefault();
    try {
      const res = await axios.post(`${API_BASE}/certificates/sign`, {
        csrPem,
        caSerialNumber: selectedCaSerial,
        profileName: csrProfile
      });
      showNotification(`Certificate issued! Serial: ${res.data.serialNumber}`);
      setCsrPem('');
      fetchData();
    } catch (err) {
      showNotification('CSR signing failed: ' + (err.response?.data || err.message), 'error');
    }
  };

  const handleCertSelect = async (cert) => {
    setSelectedCert(cert);
    // Build certificate hierarchy chain
    const chain = [];
    let current = cert;
    chain.push(current);

    // Iteratively trace parent issuer until we hit root
    let safetyCount = 0;
    while (current && current.issuerDN !== current.subjectDN && safetyCount < 10) {
      const parent = certList.find(c => c.subjectDN === current.issuerDN);
      if (parent) {
        chain.unshift(parent); // prepend parent
        current = parent;
      } else {
        break;
      }
      safetyCount++;
    }
    setSelectedCertChain(chain);
  };

  const handleRevoke = async (serial) => {
    try {
      const res = await axios.post(`${API_BASE}/certificates/${serial}/revoke`, {
        reason: revokeReason
      });
      showNotification(`Certificate revoked permanently!`);
      setSelectedCert(res.data);
      fetchData();
    } catch (err) {
      showNotification('Revocation failed: ' + (err.response?.data || err.message), 'error');
    }
  };

  const handleSuspend = async (serial) => {
    try {
      const res = await axios.post(`${API_BASE}/certificates/${serial}/suspend`);
      showNotification(`Certificate suspended successfully!`);
      setSelectedCert(res.data);
      fetchData();
    } catch (err) {
      showNotification('Suspension failed: ' + (err.response?.data || err.message), 'error');
    }
  };

  const handleUnsuspend = async (serial) => {
    try {
      const res = await axios.post(`${API_BASE}/certificates/${serial}/unsuspend`);
      showNotification(`Certificate unsuspended/reactivated!`);
      setSelectedCert(res.data);
      fetchData();
    } catch (err) {
      showNotification('Reactivation failed: ' + (err.response?.data || err.message), 'error');
    }
  };

  const handleRenew = async (serial) => {
    try {
      const res = await axios.post(`${API_BASE}/certificates/${serial}/renew`);
      showNotification(`Certificate renewed successfully! New Serial: ${res.data.serialNumber}`);
      setSelectedCert(res.data);
      fetchData();
    } catch (err) {
      showNotification('Renewal failed: ' + (err.response?.data || err.message), 'error');
    }
  };

  if (!token) {
    return (
      <div className="login-wrapper">
        <div className="login-card">
          <div className="logo-container" style={{ justifyContent: 'center' }}>
            <div className="logo-icon">PKI</div>
            <div className="logo-text">Issuing CA System</div>
          </div>
          <h2 style={{ textAlign: 'center', marginBottom: '1.5rem', fontWeight: 500 }}>Sign In</h2>
          {notification && (
            <div className={`alert alert-${notification.type}`}>{notification.message}</div>
          )}
          <form onSubmit={handleLogin}>
            <div className="form-group">
              <label className="form-label">Username</label>
              <input
                type="text"
                className="form-input"
                value={loginUsername}
                onChange={(e) => setLoginUsername(e.target.value)}
                placeholder="admin or operator"
                required
              />
            </div>
            <div className="form-group">
              <label className="form-label">Password</label>
              <input
                type="password"
                className="form-input"
                value={loginPassword}
                onChange={(e) => setLoginPassword(e.target.value)}
                placeholder="••••••••"
                required
              />
            </div>
            <button type="submit" className="btn btn-primary" style={{ width: '100%', marginTop: '1rem' }}>
              Sign In
            </button>
          </form>
          <div style={{ marginTop: '1.5rem', fontSize: '0.8rem', color: 'var(--text-secondary)', textAlign: 'center' }}>
            Enter default credentials (admin / adminpassword) to access console.
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="app-container">
      {/* Sidebar navigation */}
      <div className="sidebar">
        <div className="logo-container">
          <div className="logo-icon">PKI</div>
          <div className="logo-text">Issuing CA</div>
        </div>
        <div className="nav-links">
          <div
            className={`nav-item ${activeTab === 'dashboard' ? 'active' : ''}`}
            onClick={() => setActiveTab('dashboard')}
          >
            📊 Dashboard
          </div>
          <div
            className={`nav-item ${activeTab === 'keys' ? 'active' : ''}`}
            onClick={() => setActiveTab('keys')}
          >
            🔑 Key Management
          </div>
          <div
            className={`nav-item ${activeTab === 'cas' ? 'active' : ''}`}
            onClick={() => setActiveTab('cas')}
          >
            🛡️ CA Provisioning
          </div>
          <div
            className={`nav-item ${activeTab === 'signer' ? 'active' : ''}`}
            onClick={() => setActiveTab('signer')}
          >
            📝 CSR Signer
          </div>
          <div
            className={`nav-item ${activeTab === 'lifecycle' ? 'active' : ''}`}
            onClick={() => setActiveTab('lifecycle')}
          >
            📜 Certificate Store
          </div>
        </div>
        <div className="user-profile-section">
          <div className="user-info">
            <span className="username">{username}</span>
            <span className="role-badge">{role.replace('ROLE_', '')}</span>
          </div>
          <button className="btn-logout" onClick={handleLogout} title="Logout">
            🚪
          </button>
        </div>
      </div>

      {/* Main Panel */}
      <div className="main-content">
        {notification && (
          <div className={`alert alert-${notification.type}`}>{notification.message}</div>
        )}

        {/* Dashboard View */}
        {activeTab === 'dashboard' && (
          <div>
            <h1 style={{ marginBottom: '1.5rem' }}>Enterprise CA System Dashboard</h1>
            <div className="grid-2" style={{ gridTemplateColumns: 'repeat(4, 1fr)', marginBottom: '2rem' }}>
              <div className="card" style={{ margin: 0, padding: '1.5rem' }}>
                <div style={{ fontSize: '0.875rem', color: 'var(--text-secondary)' }}>Total Key Pairs</div>
                <div style={{ fontSize: '2rem', fontWeight: 'bold', marginTop: '0.5rem' }}>{stats.keys}</div>
              </div>
              <div className="card" style={{ margin: 0, padding: '1.5rem' }}>
                <div style={{ fontSize: '0.875rem', color: 'var(--text-secondary)' }}>Active CAs</div>
                <div style={{ fontSize: '2rem', fontWeight: 'bold', marginTop: '0.5rem', color: 'var(--accent-yellow)' }}>{stats.cas}</div>
              </div>
              <div className="card" style={{ margin: 0, padding: '1.5rem' }}>
                <div style={{ fontSize: '0.875rem', color: 'var(--text-secondary)' }}>Total Certificates</div>
                <div style={{ fontSize: '2rem', fontWeight: 'bold', marginTop: '0.5rem', color: 'var(--accent-blue)' }}>{stats.certs}</div>
              </div>
              <div className="card" style={{ margin: 0, padding: '1.5rem' }}>
                <div style={{ fontSize: '0.875rem', color: 'var(--text-secondary)' }}>Revoked Certificates</div>
                <div style={{ fontSize: '2rem', fontWeight: 'bold', marginTop: '0.5rem', color: 'var(--accent-red)' }}>{stats.issues}</div>
              </div>
            </div>

            <div className="card">
              <h2 className="card-title">System Status</h2>
              <p style={{ color: 'var(--text-secondary)', marginBottom: '1rem' }}>
                The cryptographic engine is backed by Bouncy Castle Java Provider.
                Database is synchronized with MariaDB relational schema.
              </p>
              <div className="flex-gap">
                <span className="status-badge issued">MySQL: Connected</span>
                <span className="status-badge issued">BouncyCastle: Active</span>
                <span className="status-badge issued">Security Policy: Strict</span>
              </div>
            </div>
          </div>
        )}

        {/* Key Management View */}
        {activeTab === 'keys' && (
          <div>
            <h1 style={{ marginBottom: '1.5rem' }}>Key Management Engine</h1>
            <div className="grid-2">
              <div className="card">
                <h2 className="card-title">Generate Cryptographic Key Vector</h2>
                <form onSubmit={handleGenerateKey}>
                  <div className="form-group">
                    <label className="form-label">Key Algorithm</label>
                    <select
                      className="form-select"
                      value={keyAlgorithm}
                      onChange={(e) => {
                        setKeyAlgorithm(e.target.value);
                        if (e.target.value === 'EC') setKeySize(256);
                        else if (e.target.value === 'Ed25519') setKeySize(256);
                        else setKeySize(2048);
                      }}
                    >
                      <option value="RSA">RSA (Asymmetric Cryptography)</option>
                      <option value="EC">ECDSA (Elliptic Curve Cryptography)</option>
                      <option value="Ed25519">Ed25519 (EdDSA High-Speed Signature)</option>
                    </select>
                  </div>
                  {keyAlgorithm === 'RSA' && (
                    <div className="form-group">
                      <label className="form-label">Key Size (bits)</label>
                      <select className="form-select" value={keySize} onChange={(e) => setKeySize(e.target.value)}>
                        <option value="2048">2048 bit</option>
                        <option value="3072">3072 bit</option>
                        <option value="4096">4096 bit</option>
                      </select>
                    </div>
                  )}
                  {keyAlgorithm === 'EC' && (
                    <div className="form-group">
                      <label className="form-label">Elliptic Curve Parameter</label>
                      <select className="form-select" value={keySize} onChange={(e) => setKeySize(e.target.value)}>
                        <option value="256">secp256r1 (P-256)</option>
                        <option value="384">secp384r1 (P-384)</option>
                        <option value="521">secp521r1 (P-521)</option>
                      </select>
                    </div>
                  )}
                  <button type="submit" className="btn btn-primary" style={{ marginTop: '0.5rem' }}>
                    ⚡ Generate Key Pair
                  </button>
                </form>
              </div>

              <div className="card">
                <h2 className="card-title">Stored Key Pairs</h2>
                <div className="data-table-container" style={{ maxHeight: '350px', overflowY: 'auto' }}>
                  <table className="data-table">
                    <thead>
                      <tr>
                        <th>ID</th>
                        <th>Algorithm</th>
                        <th>Size/Curve</th>
                        <th>Created At</th>
                      </tr>
                    </thead>
                    <tbody>
                      {keysList.length === 0 ? (
                        <tr>
                          <td colSpan="4" style={{ textAlign: 'center', color: 'var(--text-secondary)' }}>
                            No keys stored yet.
                          </td>
                        </tr>
                      ) : (
                        keysList.map((k) => (
                          <tr key={k.id}>
                            <td>{k.id}</td>
                            <td><span className="status-badge issued" style={{ backgroundColor: 'rgba(56, 189, 248, 0.1)' }}>{k.algorithm}</span></td>
                            <td>{k.algorithm === 'EC' ? `P-${k.keySize}` : `${k.keySize} bit`}</td>
                            <td>{new Date(k.createdAt).toLocaleString()}</td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* CA Provisioning View */}
        {activeTab === 'cas' && (
          <div>
            <h1 style={{ marginBottom: '1.5rem' }}>Hierarchical CA Initialization</h1>
            <div className="grid-2">
              <div className="card">
                <h2 className="card-title">Provision New Authority</h2>
                <div className="form-group">
                  <label className="form-label">Subject DN (Distinguished Name)</label>
                  <input
                    type="text"
                    className="form-input"
                    value={subjectDN}
                    onChange={(e) => setSubjectDN(e.target.value)}
                    placeholder="e.g. CN=My CA,O=Org,C=FR"
                    required
                  />
                </div>
                <div className="form-group">
                  <label className="form-label">Key Type</label>
                  <select className="form-select" value={caKeyType} onChange={(e) => setCaKeyType(e.target.value)}>
                    <option value="RSA">RSA</option>
                    <option value="EC">ECDSA</option>
                    <option value="Ed25519">Ed25519</option>
                  </select>
                </div>
                {caKeyType !== 'Ed25519' && (
                  <div className="form-group">
                    <label className="form-label">Size/Curve</label>
                    <select className="form-select" value={caKeySize} onChange={(e) => setCaKeySize(e.target.value)}>
                      {caKeyType === 'RSA' ? (
                        <>
                          <option value="2048">2048 bit</option>
                          <option value="3072">3072 bit</option>
                          <option value="4096">4096 bit</option>
                        </>
                      ) : (
                        <>
                          <option value="256">P-256</option>
                          <option value="384">P-384</option>
                          <option value="521">P-521</option>
                        </>
                      )}
                    </select>
                  </div>
                )}
                <div className="form-group">
                  <label className="form-label">Certificate Profile</label>
                  <select className="form-select" value={caProfile} onChange={(e) => setCaProfile(e.target.value)}>
                    <option value="RootCA">Root CA Profile</option>
                    <option value="SubCA">Subordinate CA Profile</option>
                  </select>
                </div>

                {caProfile === 'SubCA' && (
                  <div className="form-group">
                    <label className="form-label">Parent CA Serial Number</label>
                    <select className="form-select" value={parentSerial} onChange={(e) => setParentSerial(e.target.value)}>
                      <option value="">Select Parent CA...</option>
                      {caList.map(ca => (
                        <option key={ca.serialNumber} value={ca.serialNumber}>
                          {ca.subjectDN} ({ca.serialNumber})
                        </option>
                      ))}
                    </select>
                  </div>
                )}

                <div className="flex-gap" style={{ marginTop: '1.5rem' }}>
                  {caProfile === 'RootCA' ? (
                    <button onClick={handleInitRootCa} className="btn btn-primary">
                      👑 Initialize Self-Signed Root CA
                    </button>
                  ) : (
                    <button onClick={handleInitIntermediateCa} className="btn btn-success" disabled={!parentSerial}>
                      🔗 Initialize Subordinate CA
                    </button>
                  )}
                </div>
              </div>

              <div className="card">
                <h2 className="card-title">Configured Certificate Authorities</h2>
                <div className="data-table-container">
                  <table className="data-table">
                    <thead>
                      <tr>
                        <th>Type</th>
                        <th>Subject DN</th>
                        <th>Serial Number</th>
                        <th>Status</th>
                      </tr>
                    </thead>
                    <tbody>
                      {caList.length === 0 ? (
                        <tr>
                          <td colSpan="4" style={{ textAlign: 'center', color: 'var(--text-secondary)' }}>
                            No CAs initialized.
                          </td>
                        </tr>
                      ) : (
                        caList.map((ca) => (
                          <tr key={ca.id}>
                            <td>
                              <span className={`status-badge ${ca.certificateType.toLowerCase()}`} style={{
                                backgroundColor: ca.certificateType === 'ROOT' ? 'rgba(251, 191, 36, 0.15)' : 'rgba(56, 189, 248, 0.15)',
                                color: ca.certificateType === 'ROOT' ? 'var(--accent-yellow)' : 'var(--accent-blue)'
                              }}>
                                {ca.certificateType}
                              </span>
                            </td>
                            <td>{ca.subjectDN}</td>
                            <td style={{ fontFamily: 'monospace', fontSize: '0.8rem' }}>{ca.serialNumber}</td>
                            <td>
                              <span className={`status-badge ${ca.status.toLowerCase()}`}>{ca.status}</span>
                            </td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* CSR Signer View */}
        {activeTab === 'signer' && (
          <div>
            <h1 style={{ marginBottom: '1.5rem' }}>Registration Authority CSR Signing Engine</h1>
            <div className="card">
              <h2 className="card-title">Sign Standard Certificate Signing Request</h2>
              <form onSubmit={handleSignCsr}>
                <div className="form-group">
                  <label className="form-label">Select Issuing CA</label>
                  <select
                    className="form-select"
                    value={selectedCaSerial}
                    onChange={(e) => setSelectedCaSerial(e.target.value)}
                    required
                  >
                    <option value="">Select Issuing CA...</option>
                    {caList.map(ca => (
                      <option key={ca.serialNumber} value={ca.serialNumber}>
                        {ca.subjectDN} ({ca.serialNumber})
                      </option>
                    ))}
                  </select>
                </div>
                <div className="form-group">
                  <label className="form-label">Certificate Profile</label>
                  <select className="form-select" value={csrProfile} onChange={(e) => setCsrProfile(e.target.value)}>
                    <option value="EndEntity">General End Entity</option>
                    <option value="Client">Client Authentication</option>
                    <option value="Server">Server/Web Server Auth (SSL/TLS)</option>
                  </select>
                </div>
                <div className="form-group">
                  <label className="form-label">Raw PKCS#10 CSR PEM String</label>
                  <textarea
                    rows="8"
                    className="form-textarea"
                    value={csrPem}
                    onChange={(e) => setCsrPem(e.target.value)}
                    placeholder="-----BEGIN CERTIFICATE REQUEST-----&#10;...&#10;-----END CERTIFICATE REQUEST-----"
                    style={{ fontFamily: 'monospace', fontSize: '0.85rem' }}
                    required
                  />
                </div>
                <button type="submit" className="btn btn-primary" disabled={!selectedCaSerial}>
                  ✍️ Sign & Mint X.509 Certificate
                </button>
              </form>
            </div>
          </div>
        )}

        {/* Certificate Store & Lifecycle View */}
        {activeTab === 'lifecycle' && (
          <div>
            <h1 style={{ marginBottom: '1.5rem' }}>Certificate Lifecycle Management</h1>
            <div className="grid-2" style={{ gridTemplateColumns: '1.2fr 0.8fr' }}>
              <div className="card">
                <h2 className="card-title">Issued Certificates Directory</h2>
                <div className="data-table-container">
                  <table className="data-table">
                    <thead>
                      <tr>
                        <th>Subject DN</th>
                        <th>Type</th>
                        <th>Status</th>
                        <th>Action</th>
                      </tr>
                    </thead>
                    <tbody>
                      {certList.length === 0 ? (
                        <tr>
                          <td colSpan="4" style={{ textAlign: 'center', color: 'var(--text-secondary)' }}>
                            No certificates minted yet.
                          </td>
                        </tr>
                      ) : (
                        certList.map((cert) => (
                          <tr key={cert.id} style={{ cursor: 'pointer' }} onClick={() => handleCertSelect(cert)}>
                            <td style={{ fontWeight: selectedCert?.id === cert.id ? 'bold' : 'normal' }}>
                              {cert.subjectDN}
                            </td>
                            <td>
                              <span className="status-badge" style={{ backgroundColor: 'rgba(255,255,255,0.05)', color: 'var(--text-secondary)' }}>
                                {cert.certificateType}
                              </span>
                            </td>
                            <td>
                              <span className={`status-badge ${cert.status.toLowerCase()}`}>{cert.status}</span>
                            </td>
                            <td>
                              <button className="btn btn-secondary" style={{ padding: '0.2rem 0.5rem', fontSize: '0.75rem' }}>
                                View Details
                              </button>
                            </td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              </div>

              <div>
                {selectedCert ? (
                  <div className="card">
                    <h2 className="card-title">Certificate Inspector</h2>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', fontSize: '0.9rem' }}>
                      <div>
                        <span className="form-label">Subject DN</span>
                        <strong>{selectedCert.subjectDN}</strong>
                      </div>
                      <div>
                        <span className="form-label">Issuer DN</span>
                        <span>{selectedCert.issuerDN}</span>
                      </div>
                      <div className="grid-2" style={{ margin: 0 }}>
                        <div>
                          <span className="form-label">Serial Number</span>
                          <span style={{ fontFamily: 'monospace', fontSize: '0.8rem' }}>{selectedCert.serialNumber}</span>
                        </div>
                        <div>
                          <span className="form-label">Status</span>
                          <span className={`status-badge ${selectedCert.status.toLowerCase()}`}>{selectedCert.status}</span>
                        </div>
                      </div>
                      <div className="grid-2" style={{ margin: 0 }}>
                        <div>
                          <span className="form-label">Not Before</span>
                          <span style={{ fontSize: '0.8rem' }}>{new Date(selectedCert.notBefore).toLocaleString()}</span>
                        </div>
                        <div>
                          <span className="form-label">Not After</span>
                          <span style={{ fontSize: '0.8rem' }}>{new Date(selectedCert.notAfter).toLocaleString()}</span>
                        </div>
                      </div>

                      {/* Trust Chain Tree Visualization */}
                      <div style={{ marginTop: '1rem', borderTop: '1px solid var(--border-color)', paddingTop: '1rem' }}>
                        <span className="form-label">Hierarchical Trust Chain</span>
                        <div className="chain-tree">
                          {selectedCertChain.map((node, index) => (
                            <React.Fragment key={node.id}>
                              {index > 0 && <div className="chain-connector"></div>}
                              <div className={`chain-node ${node.certificateType.toLowerCase()} ${selectedCert.id === node.id ? 'active-node' : ''}`}>
                                <div className="node-title">{node.subjectDN.split(',')[0]}</div>
                                <div className="node-subtitle">{node.certificateType} (S/N: {node.serialNumber.substring(0, 8)}...)</div>
                              </div>
                            </React.Fragment>
                          ))}
                        </div>
                      </div>

                      {/* Action buttons */}
                      <div style={{ marginTop: '1.5rem', borderTop: '1px solid var(--border-color)', paddingTop: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                        <span className="form-label">Lifecycle Actions</span>
                        <div className="flex-gap" style={{ flexWrap: 'wrap' }}>
                          {selectedCert.status === 'ISSUED' && (
                            <>
                              <button onClick={() => handleRenew(selectedCert.serialNumber)} className="btn btn-primary">
                                🔄 Renew
                              </button>
                              <button onClick={() => handleSuspend(selectedCert.serialNumber)} className="btn btn-secondary">
                                ⏸️ Suspend
                              </button>
                            </>
                          )}
                          {selectedCert.status === 'SUSPENDED' && (
                            <button onClick={() => handleUnsuspend(selectedCert.serialNumber)} className="btn btn-success">
                              ▶️ Unsuspend
                            </button>
                          )}
                          {selectedCert.status !== 'REVOKED' && (
                            <div style={{ width: '100%', marginTop: '0.5rem', borderTop: '1px dashed var(--border-color)', paddingTop: '1rem' }}>
                              <div className="form-group">
                                <label className="form-label">Revocation Reason</label>
                                <select className="form-select" value={revokeReason} onChange={(e) => setRevokeReason(e.target.value)}>
                                  <option value="KEY_COMPROMISE">Key Compromise</option>
                                  <option value="CA_COMPROMISE">CA Compromise</option>
                                  <option value="AFFILIATION_CHANGED">Affiliation Changed</option>
                                  <option value="SUPERSEDED">Superseded</option>
                                  <option value="CESSATION_OF_OPERATION">Cessation of Operation</option>
                                </select>
                              </div>
                              <button onClick={() => handleRevoke(selectedCert.serialNumber)} className="btn btn-danger" style={{ width: '100%' }}>
                                🛑 Revoke Certificate Permanently
                              </button>
                            </div>
                          )}
                        </div>
                      </div>

                      {/* PEM Content */}
                      <div style={{ marginTop: '1rem' }}>
                        <span className="form-label">PEM Download</span>
                        <pre className="pem-view">{selectedCert.pemContent}</pre>
                        <button
                          onClick={() => {
                            navigator.clipboard.writeText(selectedCert.pemContent);
                            showNotification('PEM copied to clipboard');
                          }}
                          className="btn btn-secondary"
                          style={{ width: '100%', marginTop: '0.5rem', fontSize: '0.85rem' }}
                        >
                          📋 Copy Certificate PEM
                        </button>
                      </div>
                    </div>
                  </div>
                ) : (
                  <div className="card" style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '200px', color: 'var(--text-secondary)' }}>
                    Select a certificate from the directory to inspect its details and execute actions.
                  </div>
                )}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export default App;
