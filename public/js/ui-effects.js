
// Small UI effects: card tilt and header parallax glow
(function(){
  // Tilt effect for elements with .tilt class
  function handleTilt(e){
    const el = e.currentTarget;
    const rect = el.getBoundingClientRect();
    const x = (e.clientX - rect.left) / rect.width;
    const y = (e.clientY - rect.top) / rect.height;
    const rx = (y - 0.5) * -8; // rotateX
    const ry = (x - 0.5) * 12; // rotateY
    el.style.transform = `perspective(800px) rotateX(${rx}deg) rotateY(${ry}deg) scale(1.02)`;
  }
  function resetTilt(e){ e.currentTarget.style.transform = ''; }

  document.addEventListener('DOMContentLoaded', ()=>{
    document.querySelectorAll('.card-item').forEach(el=>{
      el.classList.add('tilt');
      el.addEventListener('mousemove', handleTilt);
      el.addEventListener('mouseleave', resetTilt);
    });

    // Header parallax subtle movement
    const brand = document.querySelector('.brand');
    if (brand){
      document.addEventListener('mousemove', (e)=>{
        const cx = window.innerWidth/2, cy = window.innerHeight/2;
        const dx = (e.clientX - cx)/cx;
        const dy = (e.clientY - cy)/cy;
        brand.style.transform = `translate(${dx*6}px, ${dy*4}px)`;
      });
    }
  });
})();
