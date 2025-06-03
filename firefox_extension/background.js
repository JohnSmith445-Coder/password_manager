// Background script for Kasm Workspace Firefox Extension

// Create a context menu item for opening links in Kasm Secure Browser
browser.contextMenus.create({
  id: "open-in-kasm",
  title: "Open in Kasm Secure Browser",
  contexts: ["link"]
});

// Handle the context menu item click
browser.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId === "open-in-kasm") {
    // Get the URL from the link
    const url = info.linkUrl;
    
    // Send a request to the Kasm Workspace API
    fetch("http://localhost:5000/api/launch-with-url", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ url: url }),
      credentials: "include"
    })
    .then(response => response.json())
    .then(data => {
      if (data.success) {
        // Show a notification
        browser.notifications.create({
          type: "basic",
          iconUrl: browser.runtime.getURL("icons/icon-48.png"),
          title: "Kasm Workspace",
          message: "Opening URL in Kasm Secure Browser"
        });
        
        // Open the Kasm Workspace in a new tab
        browser.tabs.create({ url: data.workspace_url });
      } else {
        // Show an error notification
        browser.notifications.create({
          type: "basic",
          iconUrl: browser.runtime.getURL("icons/icon-48.png"),
          title: "Kasm Workspace",
          message: "Error: " + data.message
        });
      }
    })
    .catch(error => {
      // Show an error notification
      browser.notifications.create({
        type: "basic",
        iconUrl: browser.runtime.getURL("icons/icon-48.png"),
        title: "Kasm Workspace",
        message: "Error: Could not connect to Kasm Workspace"
      });
    });
  }
});

// Cache for storing passwords
let passwordCache = null;

// Listen for messages from content scripts or popup
browser.runtime.onMessage.addListener((message, sender, sendResponse) => {
  // Handle getPasswords action
  if (message.action === "getPasswords") {
    // If we have cached passwords and no search term, return them immediately
    if (passwordCache && !message.searchTerm) {
      sendResponse({ success: true, passwords: passwordCache });
      return true;
    }
    
    // Fetch passwords from the API
    fetch("http://localhost:5000/api/passwords", {
      method: "GET",
      credentials: "include"
    })
    .then(response => {
      if (!response.ok) {
        throw new Error("Failed to fetch passwords");
      }
      return response.json();
    })
    .then(data => {
      // Cache the passwords
      passwordCache = data;
      
      // Filter passwords if search term is provided
      let filteredPasswords = data;
      if (message.searchTerm) {
        const searchTerm = message.searchTerm.toLowerCase();
        filteredPasswords = data.filter(password => {
          return (
            password.service.toLowerCase().includes(searchTerm) ||
            password.username.toLowerCase().includes(searchTerm) ||
            (password.category && password.category.toLowerCase().includes(searchTerm)) ||
            (password.notes && password.notes.toLowerCase().includes(searchTerm))
          );
        });
      }
      
      sendResponse({ success: true, passwords: filteredPasswords });
    })
    .catch(error => {
      console.error("Error fetching passwords:", error);
      sendResponse({ success: false, error: error.message });
    });
    
    // Return true to indicate that we will send a response asynchronously
    return true;
  }
});

// Clear password cache when the extension is unloaded
browser.runtime.onSuspend.addListener(() => {
  passwordCache = null;
});