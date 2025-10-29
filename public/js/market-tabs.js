document.addEventListener('DOMContentLoaded', function(){
  const buttons = document.querySelectorAll('.tab-btn');
  const contents = document.querySelectorAll('.tab-content');
  function activate(tab){
    buttons.forEach(b => b.classList.toggle('active', b.dataset.tab === tab));
    contents.forEach(c => c.style.display = (c.id === 'tab-' + tab) ? '' : 'none');
    // set focus
    location.hash = '#tab=' + tab;
  }
  buttons.forEach(b => b.addEventListener('click', function(){ activate(this.dataset.tab); }));
  // restore from hash
  if(location.hash && location.hash.startsWith('#tab=')){
    activate(location.hash.replace('#tab=', ''));
  } else {
    // default show market
    activate('market');
  }
});

// Messages functionality
function toggleMessages(listingId) {
  const messagesDiv = document.getElementById(`messages-${listingId}`);
  const messagesList = document.getElementById(`messages-list-${listingId}`);
  
  if (messagesDiv.style.display === 'none') {
    messagesDiv.style.display = 'block';
    loadMessages(listingId);
  } else {
    messagesDiv.style.display = 'none';
  }
}

async function loadMessages(listingId) {
  try {
    const response = await fetch(`/api/market/messages/${listingId}`);
    const data = await response.json();
    
    const messagesList = document.getElementById(`messages-list-${listingId}`);
    messagesList.innerHTML = '';
    
    if (data.messages && data.messages.length > 0) {
      data.messages.forEach(message => {
        const messageElement = document.createElement('div');
        messageElement.className = 'message-item';
        messageElement.innerHTML = `
          <div class="message-header">
            <span class="message-author">${message.author}</span>
            <span class="message-time">${new Date(message.timestamp).toLocaleString()}</span>
          </div>
          <div class="message-text">${message.text}</div>
        `;
        messagesList.appendChild(messageElement);
      });
    } else {
      messagesList.innerHTML = '<div class="no-messages">Нет сообщений</div>';
    }
  } catch (error) {
    console.error('Error loading messages:', error);
  }
}

// Auto-refresh messages every 5 seconds
setInterval(() => {
  document.querySelectorAll('.listing-messages').forEach(messagesDiv => {
    if (messagesDiv.style.display !== 'none') {
      const listingId = messagesDiv.id.replace('messages-', '');
      loadMessages(listingId);
    }
  });
}, 5000);