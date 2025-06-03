// Create a context menu item for opening links in Kasm Secure Browser
browser.contextMenus.create({
  id: "open-in-kasm-chrome",
  title: "Open in Secure Browser",
  contexts: ["link"]
});

// Listen for clicks on the context menu item
browser.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId === "open-in-kasm-chrome") {
    // The URL that was right-clicked on
    const url = info.linkUrl;
    
    // Send the URL to our Kasm Workspace API
    openInKasmChrome(url);
  }
});

// Function to open a URL in Kasm Chrome container
function openInKasmChrome(url) {
  // API endpoint for launching Chrome container
  const apiUrl = 'http://localhost:5000/api/launch-with-url';
  
  // Send a POST request to the API
  fetch(apiUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      service: 'chrome',  // Use the Chrome service
      url: url           // The URL to open
    })
  })
  .then(response => response.json())
  .then(data => {
    if (data.success) {
      // If successful, show a notification
      browser.notifications.create({
        type: 'basic',
        iconUrl: browser.runtime.getURL('icons/secure-browser-48.svg'),
        title: 'Kasm Secure Browser',
        message: 'Opening URL in secure Chrome container...'
      });
      
      // Open the container URL in a new tab
      const containerUrl = `${data.proto}://localhost:${data.host_port}`;
      browser.tabs.create({ url: containerUrl });
    } else {
      // If there was an error, show an error notification
      browser.notifications.create({
        type: 'basic',
        iconUrl: browser.runtime.getURL('icons/secure-browser-48.svg'),
        title: 'Kasm Secure Browser Error',
        message: data.error || 'Failed to open URL in secure Chrome container'
      });
    }
  })
  .catch(error => {
    console.error('Error:', error);
    // Show an error notification
    browser.notifications.create({
      type: 'basic',
      iconUrl: browser.runtime.getURL('icons/secure-browser-48.svg'),
      title: 'Kasm Secure Browser Error',
      message: 'Failed to connect to Kasm Workspace. Is it running?'
    });
  });
}