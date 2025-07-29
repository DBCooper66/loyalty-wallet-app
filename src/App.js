import React, { useState, useEffect, createContext, useContext } from 'react';
// Removed due to resolution error: import QRCode from 'qrcode.react';
import { initializeApp } from 'firebase/app';
import { getAuth, signInAnonymously, signInWithCustomToken, onAuthStateChanged, sendPasswordResetEmail } from 'firebase/auth';
import { getFirestore, doc, setDoc, getDoc, collection, query, where, getDocs, onSnapshot } from 'firebase/firestore';

// Context for Firebase and User
const FirebaseContext = createContext(null);

// Firebase Initialization and Auth Provider
const FirebaseProvider = ({ children }) => {
  const [app, setApp] = useState(null);
  const [db, setDb] = useState(null);
  const [auth, setAuth] = useState(null);
  const [userId, setUserId] = useState(null);
  const [isAuthReady, setIsAuthReady] = useState(false);
  const [currentAppId, setCurrentAppId] = useState('default-app-id'); // Initialize with a default

  useEffect(() => {
    // IMPORTANT: Replace the firebaseConfig object below with your actual Firebase project configuration.
    // You can find this in your Firebase Console -> Project settings -> Your apps -> Web app.
   const firebaseConfig = {
  apiKey: "AIzaSyChSRKMHTZNCRaw3kg2Gp80SAjTT8zpaLg",
  authDomain: "loyalty-wallet-85c82.firebaseapp.com",
  projectId: "loyalty-wallet-85c82",
  storageBucket: "loyalty-wallet-85c82.firebasestorage.app",
  messagingSenderId: "1020120619766",
  appId: "1:1020120619766:web:07b1bebef1147fe1ea6ad7",
  measurementId: "G-Z4RSCP939L"
};

    // Initialize Firebase app
    const initializedApp = initializeApp(firebaseConfig);
    const firestoreDb = getFirestore(initializedApp);
    const firebaseAuth = getAuth(initializedApp);

    // Set the currentAppId to your Firebase projectId for use in Firestore paths
    setCurrentAppId(firebaseConfig.projectId);

    setApp(initializedApp);
    setDb(firestoreDb);
    setAuth(firebaseAuth);

    // Sign in anonymously for local development
    // In a real application, you'd manage user sessions more robustly (e.g., email/password login).
    const signIn = async () => {
      try {
        await signInAnonymously(firebaseAuth);
      } catch (error) {
        console.error("Firebase authentication error:", error);
      }
    };
    signIn();

    // Listen for auth state changes to get the actual user ID
    const unsubscribe = onAuthStateChanged(firebaseAuth, (user) => {
      if (user) {
        setUserId(user.uid);
      } else {
        setUserId(crypto.randomUUID()); // Fallback for unauthenticated users
      }
      setIsAuthReady(true); // Mark auth as ready after initial check
    });

    return () => unsubscribe(); // Cleanup auth listener on unmount
  }, []); // Empty dependency array means this runs once on component mount

  return (
    <FirebaseContext.Provider value={{ app, db, auth, userId, isAuthReady, currentAppId }}>
      {children}
    </FirebaseContext.Provider>
  );
};

// Custom Hook to use Firebase Context
const useFirebase = () => useContext(FirebaseContext);

// Message Box Component (replaces alert/confirm)
const MessageBox = ({ message, onClose }) => {
  if (!message) return null;
  return (
    <div className="fixed inset-0 bg-gray-600 bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white p-6 rounded-lg shadow-xl max-w-sm w-full text-center">
        <p className="text-lg mb-4">{message}</p>
        <button
          onClick={onClose}
          className="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded-full transition duration-300 ease-in-out"
        >
          OK
        </button>
      </div>
    </div>
  );
};

// Main App Component
const App = () => {
  const [role, setRole] = useState(null);
  const [message, setMessage] = useState('');

  const showMessage = (msg) => {
    setMessage(msg);
  };

  const clearMessage = () => {
    setMessage('');
  };

  return (
    <FirebaseProvider>
      <div className="min-h-screen bg-gray-100 font-inter flex flex-col items-center justify-center p-4 sm:p-6 lg:p-8">
        <h1 className="text-4xl font-extrabold text-blue-700 mb-8 rounded-lg p-3 shadow-md bg-white text-center">Loyalty Wallet</h1>
        <div className="w-full max-w-sm sm:max-w-md md:max-w-lg lg:max-w-xl bg-white rounded-xl shadow-lg p-6 sm:p-8 md:p-10">
          {!role ? (
            <RoleSelectionPage setRole={setRole} showMessage={showMessage} />
          ) : role === 'merchant' ? (
            <MerchantFlow setRole={setRole} showMessage={showMessage} />
          ) : role === 'customer' ? (
            <CustomerFlow setRole={setRole} showMessage={showMessage} />
          ) : role === 'admin' ? (
            <AdminLoginPage setRole={setRole} showMessage={showMessage} />
          ) : null}
        </div>
        <MessageBox message={message} onClose={clearMessage} />
      </div>
    </FirebaseProvider>
  );
};

// Role Selection Page
const RoleSelectionPage = ({ setRole, showMessage }) => {
  return (
    <div className="flex flex-col space-y-4">
      <h2 className="text-2xl font-semibold text-gray-800 mb-4 text-center">Select Your Role</h2>
      <button
        onClick={() => setRole('merchant')}
        className="bg-green-500 hover:bg-green-600 text-white font-bold py-3 px-6 rounded-lg shadow-md transition duration-300 ease-in-out transform hover:scale-105 w-1/2 mx-auto"
      >
        Merchant Login
      </button>
      <button
        onClick={() => setRole('customer')}
        className="bg-blue-500 hover:bg-blue-600 text-white font-bold py-3 px-6 rounded-lg shadow-md transition duration-300 ease-in-out transform hover:scale-105 w-1/2 mx-auto"
      >
        Customer Login
      </button>
      <button
        onClick={() => setRole('admin')}
        className="bg-purple-500 hover:bg-purple-600 text-white font-bold py-3 px-6 rounded-lg shadow-md transition duration-300 ease-in-out transform hover:scale-105 w-1/2 mx-auto"
      >
        Admin Login
      </button>
    </div>
  );
};

// Merchant Flow
const MerchantFlow = ({ setRole, showMessage }) => {
  const [view, setView] = useState('login'); // 'login', 'signup', 'scanner'

  return (
    <div>
      {view === 'login' && (
        <MerchantLoginPage setView={setView} setRole={setRole} showMessage={showMessage} />
      )}
      {view === 'signup' && (
        <MerchantSignupPage setView={setView} showMessage={showMessage} />
      )}
      {view === 'scanner' && (
        <MerchantQRScanner setView={setView} showMessage={showMessage} />
      )}
    </div>
  );
};

// Merchant Login Page
const MerchantLoginPage = ({ setView, setRole, showMessage }) => {
  const { db, auth, isAuthReady, currentAppId } = useFirebase();
  const [businessPhone, setBusinessPhone] = useState('');
  const [password, setPassword] = useState('');
  const [forgotPasswordEmail, setForgotPasswordEmail] = useState('');
  const [showForgotPasswordInput, setShowForgotPasswordInput] = useState(false);


  const handleLogin = async (e) => {
    e.preventDefault();
    if (!isAuthReady || !db) {
      showMessage("Firebase not ready. Please wait.");
      return;
    }

    try {
      const merchantsRef = collection(db, `artifacts/${currentAppId}/public/data/merchants`);
      const q = query(merchantsRef, where("businessPhone", "==", businessPhone));
      const querySnapshot = await getDocs(q);

      if (querySnapshot.empty) {
        showMessage("No merchant found with this phone number.");
        return;
      }

      const merchantData = querySnapshot.docs[0].data();
      if (merchantData.password === password) {
        showMessage("Merchant login successful!");
        setView('scanner');
      } else {
        showMessage("Incorrect password.");
      }
    } catch (error) {
      console.error("Error logging in merchant:", error);
      showMessage("Login failed. Please try again.");
    }
  };

  const handleForgotPassword = async () => {
    if (!auth) {
      showMessage("Firebase Auth not ready.");
      return;
    }
    if (!forgotPasswordEmail) {
      showMessage("Please enter your email address to reset password.");
      return;
    }

    try {
      await sendPasswordResetEmail(auth, forgotPasswordEmail);
      showMessage(`If ${forgotPasswordEmail} is registered, a password reset link has been sent.`);
      setShowForgotPasswordInput(false);
      setForgotPasswordEmail('');
    } catch (error) {
      console.error("Error sending password reset email:", error);
      let errorMessage = "Failed to send password reset email. Please check the email address.";
      if (error.code === 'auth/user-not-found') {
        errorMessage = "No user found with that email address.";
      } else if (error.code === 'auth/invalid-email') {
        errorMessage = "The email address is not valid.";
      }
      showMessage(errorMessage);
    }
  };

  return (
    <div className="flex flex-col space-y-6">
      <h2 className="text-2xl font-semibold text-gray-800 text-center">Merchant Login</h2>
      <form onSubmit={handleLogin} className="flex flex-col space-y-4">
        <input
          type="text"
          placeholder="Business Phone (Login ID)"
          value={businessPhone}
          onChange={(e) => setBusinessPhone(e.target.value)}
          className="p-3 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
          required
        />
        <input
          type="password"
          placeholder="Password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          className="p-3 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
          required
        />
        <button
          type="submit"
          className="bg-indigo-600 hover:bg-indigo-700 text-white font-bold py-3 px-6 rounded-lg shadow-md transition duration-300 ease-in-out transform hover:scale-105 w-1/2 mx-auto"
        >
          Login
        </button>
      </form>

      <button
        onClick={() => setView('signup')}
        className="bg-gray-400 hover:bg-gray-500 text-white font-bold py-3 px-6 rounded-lg shadow-md transition duration-300 ease-in-out transform hover:scale-105 w-1/2 mx-auto"
      >
        Register as Merchant
      </button>

      <button
        onClick={() => setShowForgotPasswordInput(!showForgotPasswordInput)}
        className="bg-yellow-500 hover:bg-yellow-600 text-white font-bold py-2 px-4 rounded-lg shadow-md transition duration-300 ease-in-out w-1/2 mx-auto"
      >
        Forgot Password?
      </button>

      {showForgotPasswordInput && (
        <div className="flex flex-col space-y-2 mt-4">
          <input
            type="email"
            placeholder="Enter your email for password reset"
            value={forgotPasswordEmail}
            onChange={(e) => setForgotPasswordEmail(e.target.value)}
            className="p-3 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
            required
          />
          <button
            onClick={handleForgotPassword}
            className="bg-yellow-600 hover:bg-yellow-700 text-white font-bold py-2 px-4 rounded-lg shadow-md transition duration-300 ease-in-out w-1/2 mx-auto"
          >
            Send Reset Link
          </button>
        </div>
      )}

      <button
        onClick={() => setRole(null)}
        className="bg-red-500 hover:bg-red-600 text-white font-bold py-2 px-4 rounded-lg shadow-md transition duration-300 ease-in-out w-1/2 mx-auto"
      >
        Back to Role Selection
      </button>
    </div>
  );
};

// Merchant Signup Page
const MerchantSignupPage = ({ setView, showMessage }) => {
  const { db, auth, isAuthReady, currentAppId } = useFirebase();
  const [formData, setFormData] = useState({
    businessPhone: '',
    email: '', // Added email field
    password: '',
    managerName: '',
    businessName: '',
    businessAddress: '',
    postcode: '',
    businessPhoneDisplay: '',
    hoursOfOperation: '',
  });

  const handleChange = (e) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!isAuthReady || !db) {
      showMessage("Firebase not ready. Please wait.");
      return;
    }

    if (formData.password.length < 6) {
      showMessage("Password must be at least 6 characters.");
      return;
    }
    if (!formData.email) {
      showMessage("Email address is required.");
      return;
    }

    try {
      // Check if business phone or email already exists
      const merchantsRef = collection(db, `artifacts/${currentAppId}/public/data/merchants`);
      const qPhone = query(merchantsRef, where("businessPhone", "==", formData.businessPhone));
      const qEmail = query(merchantsRef, where("email", "==", formData.email));

      const [querySnapshotPhone, querySnapshotEmail] = await Promise.all([getDocs(qPhone), getDocs(qEmail)]);

      if (!querySnapshotPhone.empty) {
        showMessage("A merchant with this phone number already exists.");
        return;
      }
      if (!querySnapshotEmail.empty) {
        showMessage("A merchant with this email address already exists.");
        return;
      }

      // Add merchant data to Firestore
      const newMerchantDocRef = doc(merchantsRef, formData.businessPhone); // Use phone as document ID
      await setDoc(newMerchantDocRef, {
        ...formData,
        createdAt: new Date().toISOString(),
      });
      showMessage("Merchant registered successfully!");
      setView('login');
    } catch (error) {
      console.error("Error registering merchant:", error);
      showMessage("Registration failed. Please try again.");
    }
  };

  return (
    <div className="flex flex-col space-y-6">
      <h2 className="text-2xl font-semibold text-gray-800 text-center">Merchant Sign Up</h2>
      <form onSubmit={handleSubmit} className="flex flex-col space-y-4">
        <input
          type="text"
          name="businessPhone"
          placeholder="Business Phone (used as login ID)"
          value={formData.businessPhone}
          onChange={handleChange}
          className="p-3 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
          required
        />
        <input
          type="email"
          name="email"
          placeholder="Email Address (Required)"
          value={formData.email}
          onChange={handleChange}
          className="p-3 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
          required
        />
        <input
          type="password"
          name="password"
          placeholder="Password (min 6 characters)"
          value={formData.password}
          onChange={handleChange}
          className="p-3 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
          required
        />
        <hr className="my-2 border-gray-300" />
        <input
          type="text"
          name="managerName"
          placeholder="Manager Name"
          value={formData.managerName}
          onChange={handleChange}
          className="p-3 border border-gray-300 rounded-md"
        />
        <input
          type="text"
          name="businessName"
          placeholder="Business Name"
          value={formData.businessName}
          onChange={handleChange}
          className="p-3 border border-gray-300 rounded-md"
        />
        <input
          type="text"
          name="businessAddress"
          placeholder="Business Address"
          value={formData.businessAddress}
          onChange={handleChange}
          className="p-3 border border-gray-300 rounded-md"
        />
        <input
          type="text"
          name="postcode"
          placeholder="Postcode"
          value={formData.postcode}
          onChange={handleChange}
          className="p-3 border border-gray-300 rounded-md"
        />
        <input
          type="text"
          name="businessPhoneDisplay"
          placeholder="Display Phone Number"
          value={formData.businessPhoneDisplay}
          onChange={handleChange}
          className="p-3 border border-gray-300 rounded-md"
        />
        <input
          type="text"
          name="hoursOfOperation"
          placeholder="Hours of Operation"
          value={formData.hoursOfOperation}
          onChange={handleChange}
          className="p-3 border border-gray-300 rounded-md"
        />
        <button
          type="submit"
          className="bg-green-600 hover:bg-green-700 text-white font-bold py-3 px-6 rounded-lg shadow-md transition duration-300 ease-in-out transform hover:scale-105 w-1/2 mx-auto"
        >
          Submit
        </button>
      </form>
      <button
        onClick={() => setView('login')}
        className="bg-gray-400 hover:bg-gray-500 text-white font-bold py-2 px-4 rounded-lg shadow-md transition duration-300 ease-in-out w-1/2 mx-auto"
      >
        Back to Login
      </button>
    </div>
  );
};

// Merchant QR Scanner (Simulated)
const MerchantQRScanner = ({ setView, showMessage }) => {
  const { db, auth, isAuthReady, currentAppId } = useFirebase();
  const [scannedData, setScannedData] = useState('');
  const [customerName, setCustomerName] = useState('');
  const [customerVisits, setCustomerVisits] = useState(0);

  const handleScan = async () => {
    if (!isAuthReady || !db) {
      showMessage("Firebase not ready. Please wait.");
      return;
    }

    if (!scannedData) {
      showMessage("Please enter customer QR data (phone number) to simulate scan.");
      return;
    }

    try {
      const customerDocRef = doc(db, `artifacts/${currentAppId}/public/data/customers`, scannedData);
      const customerDocSnap = await getDoc(customerDocRef);

      if (customerDocSnap.exists()) {
        const customerData = customerDocSnap.data();
        const currentVisits = customerData.visits || 0;
        const newVisits = currentVisits + 1;

        await setDoc(customerDocRef, { ...customerData, visits: newVisits }, { merge: true });

        setCustomerName(customerData.nickname || 'Unknown Customer');
        setCustomerVisits(newVisits);
        showMessage(`Customer ${customerData.nickname || scannedData} checked in! Total visits: ${newVisits}`);
      } else {
        // If customer doesn't exist, create a new entry
        await setDoc(customerDocRef, {
          phone: scannedData,
          nickname: `Customer_${scannedData.substring(scannedData.length - 4)}`, // Auto-generate nickname
          visits: 1,
          createdAt: new Date().toISOString(),
        });
        setCustomerName(`Customer_${scannedData.substring(scannedData.length - 4)}`);
        setCustomerVisits(1);
        showMessage(`New customer ${scannedData} checked in for the first time!`);
      }
    } catch (error) {
      console.error("Error processing scan:", error);
      showMessage("Error processing scan. Please try again.");
    }
  };

  return (
    <div className="flex flex-col space-y-6 items-center">
      <h2 className="text-2xl font-semibold text-gray-800 text-center">Simulate QR Scan</h2>
      <p className="text-gray-600 text-center">
        Enter the customer's phone number (which acts as their QR data) below to simulate a scan.
      </p>
      <input
        type="text"
        placeholder="Enter Customer Phone Number (e.g., 1234567890)"
        value={scannedData}
        onChange={(e) => setScannedData(e.target.value)}
        className="p-3 border border-gray-300 rounded-md w-full max-w-sm focus:ring-blue-500 focus:border-blue-500"
      />
      <button
        onClick={handleScan}
        className="bg-teal-600 hover:bg-teal-700 text-white font-bold py-3 px-6 rounded-lg shadow-md transition duration-300 ease-in-out transform hover:scale-105 w-1/2 mx-auto"
      >
        Simulate Scan
      </button>

      {customerName && (
        <div className="mt-6 p-4 bg-blue-50 rounded-lg shadow-inner text-center w-full max-w-sm">
          <p className="text-lg font-medium text-gray-700">Last Scanned Customer:</p>
          <p className="text-xl font-bold text-blue-800">{customerName}</p>
          <p className="text-md text-gray-600">Total Visits: <span className="font-bold text-blue-700">{customerVisits}</span></p>
        </div>
      )}

      <button
        onClick={() => setView('login')}
        className="bg-gray-400 hover:bg-gray-500 text-white font-bold py-2 px-4 rounded-lg shadow-md transition duration-300 ease-in-out w-1/2 mx-auto"
      >
        Back to Merchant Login
      </button>
    </div>
  );
};

// Customer Flow
const CustomerFlow = ({ setRole, showMessage }) => {
  const [view, setView] = useState('login'); // 'login', 'dashboard'

  return (
    <div>
      {view === 'login' && (
        <CustomerLoginPage setView={setView} setRole={setRole} showMessage={showMessage} />
      )}
      {view === 'dashboard' && (
        <CustomerDashboard setView={setView} showMessage={showMessage} />
      )}
    </div>
  );
};

// Customer Login Page
const CustomerLoginPage = ({ setView, setRole, showMessage }) => {
  const { db, auth, isAuthReady, currentAppId } = useFirebase();
  const [phone, setPhone] = useState('');
  const [nickname, setNickname] = useState('');
  const [email, setEmail] = useState('');
  const [forgotPasswordEmail, setForgotPasswordEmail] = useState('');
  const [showForgotPasswordInput, setShowForgotPasswordInput] = useState(false);

  const handleLogin = async (e) => {
    e.preventDefault();
    if (!isAuthReady || !db) {
      showMessage("Firebase not ready. Please wait.");
      return;
    }
    if (!email) {
      showMessage("Email address is required.");
      return;
    }

    try {
      const customerDocRef = doc(db, `artifacts/${currentAppId}/public/data/customers`, phone);
      const customerDocSnap = await getDoc(customerDocRef);

      if (customerDocSnap.exists()) {
        const customerData = customerDocSnap.data();
        if (customerData.nickname === nickname && customerData.email === email) {
          showMessage("Customer login successful!");
          localStorage.setItem('currentCustomerPhone', phone);
          localStorage.setItem('currentCustomerNickname', nickname);
          localStorage.setItem('currentCustomerEmail', email);
          setView('dashboard');
        } else {
          showMessage("Incorrect nickname or email for this phone number.");
        }
      } else {
        await setDoc(customerDocRef, {
          phone: phone,
          nickname: nickname,
          email: email,
          visits: 0,
          createdAt: new Date().toISOString(),
        });
        showMessage("New customer registered and logged in!");
        localStorage.setItem('currentCustomerPhone', phone);
        localStorage.setItem('currentCustomerNickname', nickname);
        localStorage.setItem('currentCustomerEmail', email);
        setView('dashboard');
      }
    } catch (error) {
      console.error("Error logging in/registering customer:", error);
      showMessage("Login/Registration failed. Please try again.");
    }
  };

  const handleForgotPassword = async () => {
    if (!auth) {
      showMessage("Firebase Auth not ready.");
      return;
    }
    if (!forgotPasswordEmail) {
      showMessage("Please enter your email address to reset password.");
      return;
    }

    try {
      await sendPasswordResetEmail(auth, forgotPasswordEmail);
      showMessage(`If ${forgotPasswordEmail} is registered, a password reset link has been sent.`);
      setShowForgotPasswordInput(false);
      setForgotPasswordEmail('');
    } catch (error) {
      console.error("Error sending password reset email:", error);
      let errorMessage = "Failed to send password reset email. Please check the email address.";
      if (error.code === 'auth/user-not-found') {
        errorMessage = "No user found with that email address.";
      } else if (error.code === 'auth/invalid-email') {
        errorMessage = "The email address is not valid.";
      }
      showMessage(errorMessage);
    }
  };

  return (
    <div className="flex flex-col space-y-6">
      <h2 className="text-2xl font-semibold text-gray-800 text-center">Customer Login / Register</h2>
      <form onSubmit={handleLogin} className="flex flex-col space-y-4">
        <input
          type="text"
          placeholder="Your Phone Number (e.g., 1234567890)"
          value={phone}
          onChange={(e) => setPhone(e.target.value)}
          className="p-3 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
          required
        />
        <input
          type="email"
          placeholder="Your Email Address (Required)"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          className="p-3 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
          required
        />
        <input
          type="text"
          placeholder="Your Nickname"
          value={nickname}
          onChange={(e) => setNickname(e.target.value)}
          className="p-3 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
          required
        />
        <button
          type="submit"
          className="bg-blue-600 hover:bg-blue-700 text-white font-bold py-3 px-6 rounded-lg shadow-md transition duration-300 ease-in-out transform hover:scale-105 w-1/2 mx-auto"
        >
          Login / Register
        </button>
      </form>

      <button
        onClick={() => setShowForgotPasswordInput(!showForgotPasswordInput)}
        className="bg-yellow-500 hover:bg-yellow-600 text-white font-bold py-2 px-4 rounded-lg shadow-md transition duration-300 ease-in-out w-1/2 mx-auto"
      >
        Forgot Password?
      </button>

      {showForgotPasswordInput && (
        <div className="flex flex-col space-y-2 mt-4">
          <input
            type="email"
            placeholder="Enter your email for password reset"
            value={forgotPasswordEmail}
            onChange={(e) => setForgotPasswordEmail(e.target.value)}
            className="p-3 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
            required
          />
          <button
            onClick={handleForgotPassword}
            className="bg-yellow-600 hover:bg-yellow-700 text-white font-bold py-2 px-4 rounded-lg shadow-md transition duration-300 ease-in-out w-1/2 mx-auto"
          >
            Send Reset Link
          </button>
        </div>
      )}

      <button
        onClick={() => setRole(null)}
        className="bg-red-500 hover:bg-red-600 text-white font-bold py-2 px-4 rounded-lg shadow-md transition duration-300 ease-in-out w-1/2 mx-auto"
      >
        Back to Role Selection
      </button>
    </div>
  );
};

// Customer Dashboard
const CustomerDashboard = ({ setView, showMessage }) => {
  const { db, auth, isAuthReady, currentAppId } = useFirebase();
  const [nickname, setNickname] = useState(localStorage.getItem('currentCustomerNickname') || 'Guest');
  const [phone, setPhone] = useState(localStorage.getItem('currentCustomerPhone') || '');
  const [email, setEmail] = useState(localStorage.getItem('currentCustomerEmail') || '');
  const [visits, setVisits] = useState(0);

  useEffect(() => {
    if (!isAuthReady || !db || !phone) {
      return;
    }

    const customerDocRef = doc(db, `artifacts/${currentAppId}/public/data/customers`, phone);

    const unsubscribe = onSnapshot(customerDocRef, (docSnap) => {
      if (docSnap.exists()) {
        const data = docSnap.data();
        setNickname(data.nickname);
        setVisits(data.visits || 0);
        setEmail(data.email || '');
      } else {
        console.warn("Customer data not found in Firestore. Logging out.");
        handleLogout();
      }
    }, (error) => {
      console.error("Error listening to customer data:", error);
      showMessage("Error loading customer data.");
    });

    return () => unsubscribe();
  }, [db, isAuthReady, phone, showMessage, currentAppId]);

  const handleLogout = () => {
    localStorage.removeItem('currentCustomerPhone');
    localStorage.removeItem('currentCustomerNickname');
    localStorage.removeItem('currentCustomerEmail');
    setNickname('Guest');
    setPhone('');
    setEmail('');
    setVisits(0);
    setView('login');
  };

  if (!phone) {
    return (
      <div className="text-center">
        <p className="text-lg text-red-500 mb-4">Please log in to view your dashboard.</p>
        <button
          onClick={() => setView('login')}
          className="bg-blue-500 hover:bg-blue-600 text-white font-bold py-2 px-4 rounded-lg shadow-md transition duration-300 ease-in-out w-1/2 mx-auto"
        >
          Go to Login
        </button>
      </div>
    );
  }

  return (
    <div className="flex flex-col items-center space-y-6 p-4">
      <h2 className="text-3xl font-bold text-blue-700">Welcome, {nickname}!</h2>
      <p className="text-xl text-gray-700">Your Phone: <span className="font-semibold">{phone}</span></p>
      <p className="text-xl text-gray-700">Your Email: <span className="font-semibold">{email}</span></p>
      <p className="text-xl text-gray-700">Total Visits: <span className="font-bold text-green-600">{visits}</span></p>

      <div className="p-6 bg-white rounded-lg shadow-md text-center">
        <p className="text-lg font-medium text-gray-800 mb-4">Your QR Code (for Merchant Check-In):</p>
        <div className="p-2 bg-white rounded-md shadow-inner border border-dashed border-gray-300 h-48 flex items-center justify-center text-gray-500 text-sm">
          {/* Placeholder for QR Code - qrcode.react could not be resolved */}
          <p>QR Code for: <span className="font-bold">{phone}</span></p>
          <p className="mt-2 text-xs">(QR code generation library could not be loaded in this environment. Please use the phone number directly for simulation.)</p>
        </div>
        <p className="text-sm text-gray-500 mt-2">Merchants will use this phone number to check you in.</p>
      </div>

      <p className="text-lg text-gray-600 italic">Visit Tracker and Offers Coming Soon...</p>

      <button
        onClick={handleLogout}
        className="bg-red-600 hover:bg-red-700 text-white font-bold py-3 px-6 rounded-lg shadow-md transition duration-300 ease-in-out transform hover:scale-105 w-1/2 mx-auto"
      >
        Logout
      </button>
    </div>
  );
};

// Admin Login Page (Placeholder)
const AdminLoginPage = ({ setRole, showMessage }) => {
  const { auth } = useFirebase();
  const [adminEmail, setAdminEmail] = useState('');
  const [showForgotPasswordInput, setShowForgotPasswordInput] = useState(false);

  const handleForgotPassword = async () => {
    if (!auth) {
      showMessage("Firebase Auth not ready.");
      return;
    }
    if (!adminEmail) {
      showMessage("Please enter your email address to reset password.");
      return;
    }

    try {
      await sendPasswordResetEmail(auth, adminEmail);
      showMessage(`If ${adminEmail} is registered, a password reset link has been sent.`);
      setShowForgotPasswordInput(false);
      setAdminEmail('');
    } catch (error) {
      console.error("Error sending password reset email:", error);
      let errorMessage = "Failed to send password reset email. Please check the email address.";
      if (error.code === 'auth/user-not-found') {
        errorMessage = "No user found with that email address.";
      } else if (error.code === 'auth/invalid-email') {
        errorMessage = "The email address is not valid.";
      }
      showMessage(errorMessage);
    }
  };

  return (
    <div className="flex flex-col space-y-4 items-center">
      <h2 className="text-2xl font-semibold text-gray-800 text-center">Admin Login</h2>
      <p className="text-gray-600 text-center">Admin functionality is not implemented in this simulation.</p>

      <button
        onClick={() => setShowForgotPasswordInput(!showForgotPasswordInput)}
        className="bg-yellow-500 hover:bg-yellow-600 text-white font-bold py-2 px-4 rounded-lg shadow-md transition duration-300 ease-in-out w-1/2 mx-auto"
      >
        Forgot Password?
      </button>

      {showForgotPasswordInput && (
        <div className="flex flex-col space-y-2 mt-4">
          <input
            type="email"
            placeholder="Enter your email for password reset"
            value={adminEmail}
            onChange={(e) => setAdminEmail(e.target.value)}
            className="p-3 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
            required
          />
          <button
            onClick={handleForgotPassword}
            className="bg-yellow-600 hover:bg-yellow-700 text-white font-bold py-2 px-4 rounded-lg shadow-md transition duration-300 ease-in-out w-1/2 mx-auto"
          >
            Send Reset Link
          </button>
        </div>
      )}

      <button
        onClick={() => setRole(null)}
        className="bg-red-500 hover:bg-red-600 text-white font-bold py-2 px-4 rounded-lg shadow-md transition duration-300 ease-in-out w-1/2 mx-auto"
      >
        Back to Role Selection
      </button>
    </div>
  );
};

export default App;
