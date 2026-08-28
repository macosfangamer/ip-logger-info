async function loadLogs() {
  const q = document.getElementById('search').value;
  const response = await fetch('/api/logs?limit=500&q=' + encodeURIComponent(q));
  if (!response.ok) return;
  const rows = await response.json();
  document.getElementById('logs').innerHTML = rows.map(r => `<tr><td>${r.id}</td><td>${escapeHtml(r.ip_address)}</td><td>${escapeHtml(r.timestamp)}</td><td class="ua">${escapeHtml(r.user_agent)}</td><td>${escapeHtml(r.endpoint)}</td><td><button onclick="removeLog(${r.id})">Delete</button></td></tr>`).join('');
}
async function removeLog(id) { if (!confirm('Delete this record?')) return; await fetch('/api/logs/' + id, {method:'DELETE'}); loadLogs(); }
async function purge() { if (!confirm('Delete records older than the configured retention period?')) return; const r = await fetch('/api/logs/purge', {method:'POST'}); const d = await r.json(); alert('Deleted ' + d.deleted + ' records.'); loadLogs(); }
function escapeHtml(value) { const d=document.createElement('div'); d.textContent=value ?? ''; return d.innerHTML; }
loadLogs();
