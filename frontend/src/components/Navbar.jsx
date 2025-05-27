import { Link } from "react-router";

const Navbar = () => {
  return (
    <header className="w-full py-6 px-8 flex justify-between items-center bg-gradient-to-br from-gray-900 via-gray-800 to-blue-900 shadow">
      <span className="text-2xl font-extrabold text-blue-400 tracking-tight">
        <Link to="/" className="hover:underline">
          Ransomware<span className="text-white">Guard</span>
        </Link>
      </span>
      <nav className="space-x-4">
        <Link to="/scan/file" className={navBtnStyle}>File Scan</Link>
        <Link to="/scan/url" className={navBtnStyle}>URL Scan</Link>
      </nav>
    </header>
  );
};

const navBtnStyle =
  "inline-block px-4 py-2 rounded-full bg-blue-500 text-white font-semibold hover:bg-blue-600 transition";

export default Navbar;