import './App.css'
import OAuthDemo from './components/OAuthDemo'

function App() {
  return (
    <div className="App">
      <header className="App-header">
        <h1>AIP React Demo Client</h1>
        <p>Demonstrates OAuth authentication with AIP using React and TypeScript</p>
      </header>
      <main>
        <OAuthDemo />
      </main>
    </div>
  )
}

export default App