(function(){
  // Preserve selects in URL for alerts filters (if present)
  const sev = document.querySelector('[data-filter="severity"]');
  const st  = document.querySelector('[data-filter="status"]');
  function apply(){
    const url = new URL(window.location.href);
    if (sev) url.searchParams.set("severity", sev.value);
    if (st)  url.searchParams.set("status", st.value);
    window.location.href = url.toString();
  }
  if (sev) sev.addEventListener("change", apply);
  if (st)  st.addEventListener("change", apply);
})();
