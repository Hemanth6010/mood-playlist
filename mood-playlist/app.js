// ==== CONFIG ====
// 👇 your client ID from Spotify dashboard
const CLIENT_ID = "2f9c7addc1924f78a1077fa231e36ae8";

// This must match EXACTLY the redirect URI in Spotify dashboard
const REDIRECT_URI = "https://spotify-moodify.netlify.app/";

// Scopes we need: create & edit playlists
const SCOPES = [
  "playlist-modify-public",
  "playlist-modify-private",
  "user-read-email"
].join(" ");

// HTML elements
const loginBtn = document.getElementById("login-btn");
const loggedInSection = document.getElementById("logged-in-section");
const userInfoEl = document.getElementById("user-info");
const moodInput = document.getElementById("mood-input");
const generateBtn = document.getElementById("generate-btn");
const statusEl = document.getElementById("status");

// ===== UTIL: show status =====
function setStatus(msg) {
  statusEl.textContent = msg || "";
}

// ===== PKCE HELPERS =====

// Generate random string for code_verifier
function generateRandomString(length) {
  const possible =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
  let text = "";
  for (let i = 0; i < length; i++) {
    text += possible.charAt(Math.floor(Math.random() * possible.length));
  }
  return text;
}

// SHA256 + base64url for code_challenge
async function sha256(plain) {
  const encoder = new TextEncoder();
  const data = encoder.encode(plain);
  return await window.crypto.subtle.digest("SHA-256", data);
}

function base64urlencode(a) {
  let str = "";
  const bytes = new Uint8Array(a);
  const len = bytes.byteLength;
  for (let i = 0; i < len; i++) {
    str += String.fromCharCode(bytes[i]);
  }
  return btoa(str)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

async function generateCodeChallenge(codeVerifier) {
  const digest = await sha256(codeVerifier);
  return base64urlencode(digest);
}

// ===== LOGIN FLOW =====

// 1) When user clicks login -> redirect to Spotify
loginBtn.addEventListener("click", async () => {
  try {
    const codeVerifier = generateRandomString(64);
    const codeChallenge = await generateCodeChallenge(codeVerifier);

    // Save the verifier to localStorage (we'll need it after redirect)
    window.localStorage.setItem("spotify_code_verifier", codeVerifier);

    const params = new URLSearchParams({
      client_id: CLIENT_ID,
      response_type: "code",
      redirect_uri: REDIRECT_URI,
      code_challenge_method: "S256",
      code_challenge: codeChallenge,
      scope: SCOPES,
    });

    const authUrl = `https://accounts.spotify.com/authorize?${params.toString()}`;
    window.location = authUrl;
  } catch (err) {
    console.error(err);
    alert("Login failed, check console.");
  }
});

// 2) After redirect back, Spotify gives ?code=...
async function handleRedirectCallback() {
  const urlParams = new URLSearchParams(window.location.search);
  const code = urlParams.get("code");

  if (!code) {
    // no code => user not logged in yet
    return;
  }

  // Remove ?code from URL (clean UI)
  window.history.replaceState({}, document.title, REDIRECT_URI);

  const codeVerifier = window.localStorage.getItem("spotify_code_verifier");
  if (!codeVerifier) {
    alert("No code_verifier in storage. Try logging in again.");
    return;
  }

  // Exchange code for access token
  const body = new URLSearchParams({
    client_id: CLIENT_ID,
    grant_type: "authorization_code",
    code: code,
    redirect_uri: REDIRECT_URI,
    code_verifier: codeVerifier,
  });

  try {
    const response = await fetch("https://accounts.spotify.com/api/token", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body,
    });

    if (!response.ok) {
      const errText = await response.text();
      console.error("Token error:", errText);
      alert("Failed to get access token. Check console.");
      return;
    }

    const data = await response.json();
    const { access_token, expires_in } = data;

    // Store access token (simple version – no refresh handling yet)
    window.localStorage.setItem("spotify_access_token", access_token);
    window.localStorage.setItem("spotify_token_expires_in", String(expires_in));
    window.localStorage.removeItem("spotify_code_verifier");

    await onLoggedIn(access_token);
  } catch (err) {
    console.error(err);
    alert("Error getting access token. Check console.");
  }
}

async function fetchSpotifyProfile(accessToken) {
  const res = await fetch("https://api.spotify.com/v1/me", {
    headers: {
      Authorization: `Bearer ${accessToken}`,
    },
  });

  if (!res.ok) {
    throw new Error("Failed to get profile");
  }

  return await res.json();
}

async function onLoggedIn(accessToken) {
  try {
    const profile = await fetchSpotifyProfile(accessToken);

    // Show user info
    userInfoEl.textContent = `Logged in as ${profile.display_name || profile.id}`;
    loginBtn.classList.add("hidden");
    loggedInSection.classList.remove("hidden");
    setStatus("Ready. Type a mood and generate a playlist.");
  } catch (err) {
    console.error(err);
    alert("Error loading profile. Maybe token expired.");
  }
}

// On page load: check if we already have token OR just got code
window.addEventListener("load", async () => {
  const accessToken = window.localStorage.getItem("spotify_access_token");

  if (accessToken) {
    try {
      await onLoggedIn(accessToken);
    } catch (err) {
      console.warn("Stored token invalid, clearing.", err);
      window.localStorage.removeItem("spotify_access_token");
    }
  } else {
    await handleRedirectCallback();
  }
});

// ===== PLAYLIST GENERATION =====

async function getCurrentUser(accessToken) {
  const res = await fetch("https://api.spotify.com/v1/me", {
    headers: {
      Authorization: `Bearer ${accessToken}`,
    },
  });

  if (!res.ok) throw new Error("Failed to get current user");

  return res.json();
}

// Simple search (used as fallback / unknown mood)
async function searchTracksByMood(accessToken, mood) {
  const params = new URLSearchParams({
    q: mood,
    type: "track",
    limit: "30",
  });

  const res = await fetch(
    `https://api.spotify.com/v1/search?${params.toString()}`,
    {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    }
  );

  if (!res.ok) {
    const txt = await res.text();
    console.error("Search error:", txt);
    throw new Error("Spotify search failed");
  }

  const data = await res.json();
  return (data.tracks && data.tracks.items) || [];
}

// Mood → recommendations API
async function getRecommendationsByMood(accessToken, mood) {
  const base = "https://api.spotify.com/v1/recommendations";

  let opts = {
    limit: 30,
    seed_genres: "pop",
  };

  const m = mood.toLowerCase();

  if (m.includes("happy")) {
    opts.target_valence = 0.9;
    opts.target_energy = 0.8;
  } else if (m.includes("sad")) {
    opts.target_valence = 0.2;
    opts.target_energy = 0.3;
  } else if (m.includes("chill")) {
    opts.target_energy = 0.3;
    opts.target_danceability = 0.4;
  } else if (m.includes("workout")) {
    opts.target_energy = 0.9;
    opts.target_tempo = 130;
  } else if (m.includes("study")) {
    opts.target_energy = 0.2;
    opts.target_instrumentalness = 0.8;
  } else {
    // unknown mood → use title search
    return searchTracksByMood(accessToken, mood);
  }

  const params = new URLSearchParams();
  Object.entries(opts).forEach(([key, value]) => {
    params.append(key, String(value));
  });

  try {
    const res = await fetch(`${base}?${params.toString()}`, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    });

    if (!res.ok) {
      const txt = await res.text();
      console.error("Recommendations error:", txt);
      // fall back instead of killing the flow
      return searchTracksByMood(accessToken, mood);
    }

    const data = await res.json();
    return data.tracks || [];
  } catch (err) {
    console.error("Recommendations fetch failed:", err);
    return searchTracksByMood(accessToken, mood);
  }
}

async function createPlaylist(accessToken, userId, name, description = "") {
  const res = await fetch(`https://api.spotify.com/v1/users/${userId}/playlists`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      name,
      description,
      public: false,
    }),
  });

  if (!res.ok) {
    const txt = await res.text();
    console.error("Create playlist error:", txt);
    throw new Error("Failed to create playlist");
  }

  return res.json();
}

async function addTracksToPlaylist(accessToken, playlistId, uris) {
  const res = await fetch(
    `https://api.spotify.com/v1/playlists/${playlistId}/tracks`,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        uris,
      }),
    }
  );

  if (!res.ok) {
    const txt = await res.text();
    console.error("Add tracks error:", txt);
    throw new Error("Failed to add tracks");
  }

  return res.json();
}

// When user clicks "Generate Playlist"
generateBtn.addEventListener("click", async () => {
  const mood = moodInput.value.trim();
  if (!mood) {
    setStatus("Type a mood first, boss.");
    return;
  }

  const accessToken = window.localStorage.getItem("spotify_access_token");
  if (!accessToken) {
    setStatus("Not logged in. Click Login with Spotify again.");
    return;
  }

  generateBtn.disabled = true;
  setStatus("Generating playlist...");

  try {
    // 1) Get user ID
    const user = await getCurrentUser(accessToken);

    // 2) Get tracks based on mood
    const tracks = await getRecommendationsByMood(accessToken, mood);
    if (!tracks.length) {
      setStatus("No tracks found for that mood. Try another word.");
      generateBtn.disabled = false;
      return;
    }

    const uris = tracks.map((t) => t.uri);

    // 3) Create playlist
    const playlistName = `${mood} Mood Playlist`;
    const description = `Auto-generated playlist for mood: ${mood}`;
    const playlist = await createPlaylist(
      accessToken,
      user.id,
      playlistName,
      description
    );

    // 4) Add tracks
    await addTracksToPlaylist(accessToken, playlist.id, uris);

    setStatus(`Done! Playlist "${playlistName}" created in your Spotify account.`);
  } catch (err) {
    console.error(err);
    setStatus(err.message || "Something broke. Check console (F12 → Console).");
  } finally {
    generateBtn.disabled = false;
  }
});
