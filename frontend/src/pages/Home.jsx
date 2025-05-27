
import { Link } from "react-router";

const Home = () => {
  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-gray-800 to-blue-900 flex flex-col">


      {/* Hero Section */}
      <main className="flex flex-1 flex-col items-center justify-center text-center px-4">
        <h1 className="text-4xl md:text-6xl font-extrabold text-white mb-4 drop-shadow-lg">
          Protect Your Digital World
        </h1>
        <p className="text-lg md:text-2xl text-blue-100 mb-8 max-w-2xl">
          Scan files, URLs, and emails for ransomware threats using AI-powered detection. Stay one step ahead of cybercriminals and keep your data safe.
        </p>
        <div className="flex flex-wrap gap-4 justify-center mb-12">
          <Link to="/scan/file" className={ctaBtnStyle}>Scan a File</Link>
          <Link to="/scan/url" className={ctaBtnStyleAlt}>Scan a URL</Link>
        </div>
        <div className="flex flex-col md:flex-row gap-6 justify-center items-center mt-8">
          <FeatureCard
            icon="🛡️"
            title="Real-Time Protection"
            desc="Instantly scan and detect ransomware in files, links, and emails."
          />
          <FeatureCard
            icon="🤖"
            title="AI-Powered"
            desc="Advanced machine learning models trained on real ransomware data."
          />
          <FeatureCard
            icon="🔒"
            title="Privacy First"
            desc="Your data is never stored. All scans are processed securely."
          />
        </div>
      </main>

      {/* Footer */}
      <footer className="w-full py-4 text-center text-blue-200 text-sm bg-transparent mt-auto">
        &copy; {new Date().getFullYear()} RansomwareGuard. All rights reserved.
      </footer>
    </div>
  );
};

const ctaBtnStyle =
  "px-8 py-3 rounded-full bg-gradient-to-r from-blue-500 to-blue-700 text-white font-bold text-lg shadow-lg hover:from-blue-600 hover:to-blue-800 transition";
const ctaBtnStyleAlt =
  "px-8 py-3 rounded-full bg-blue-900 text-blue-200 font-bold text-lg border border-blue-700 hover:bg-blue-800 hover:text-white transition";

const FeatureCard = ({ icon, title, desc }) => (
  <div className="bg-gray-800 bg-opacity-80 rounded-xl shadow-lg p-6 w-72 flex flex-col items-center">
    <div className="text-4xl mb-2">{icon}</div>
    <h3 className="text-xl font-bold text-white mb-1">{title}</h3>
    <p className="text-blue-100 text-sm">{desc}</p>
  </div>
);

export default Home;