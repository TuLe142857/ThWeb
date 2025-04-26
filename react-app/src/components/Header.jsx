import './Header.css'

function Header() {
  return (
    <div className="header-container">
      <a href="/">MainMenu</a>
      <div>
        <button>Login</button>
        <button>Logout</button>
      </div>
    </div>
  )
}

export default Header
