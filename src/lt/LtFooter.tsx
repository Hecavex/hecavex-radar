export function LtFooter() {
  return (
    <footer className="site-footer">
      <div className="footer-inner">
        <div className="footer-brand">
          <strong>RADARAS</strong>
          <span>
            Viešas gynybinis <a href="https://hecavex.com/lt/">HECAVEX</a> tyrimas. Signalai yra tyrimo
            kryptys, o ne priskyrimas ar kenkėjiškumo įrodymas.
          </span>
          <span>Aktyviai prižiūrima geriausių pastangų principu · be paskyrų · be pavojingų aktyvių nuorodų</span>
        </div>
        <nav aria-label="Poraštė">
          <a href="https://hecavex.com/lt/tyrimai/">Tyrimai</a>
          <a href="/lt/">Radaras</a>
          <a href="/lt/pokyciai/">Pokyčiai</a>
          <a href="/lt/prekes-zenklai/">Prekių ženklai</a>
          <a href="/lt/metodologija/">Metodologija</a>
          <a href="/docs/">Techninė dokumentacija</a>
          <a href="/.well-known/security.txt">Saugumas</a>
          <a href="mailto:info@hecavex.com?subject=HECAVEX%20Radar%20klaidingas%20teigiamas%20rezultatas">Pataisymai</a>
          <a href="https://hecavex.com/lt/privatumas/">Privatumas</a>
        </nav>
      </div>
    </footer>
  );
}
