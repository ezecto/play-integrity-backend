const express = require('express');
const cors = require('cors');  // Import CORS
const { GoogleAuth } = require('google-auth-library');
const axios = require('axios');

const app = express();
app.use(express.json());
app.use(cors());  // Enable CORS

// Load the service account credentials
const auth = new GoogleAuth({
  keyFile: './unirent-ncs-6779a73fe544.json',
  scopes: ['https://www.googleapis.com/auth/playintegrity'],
});

// Function to verify the integrity token
async function verifyIntegrityToken(integrityToken) {
  const packageName = "com.unirent"; 
  const url = `https://playintegrity.googleapis.com/v1/${packageName}:decodeIntegrityToken`;

  try {
    // Get the access token
    const client = await auth.getClient();
    const accessToken = await client.getAccessToken(); // Dynamically retrieve the access token
    //console.log("Access token: " + JSON.stringify(accessToken,null,2));
    console.log("Access token: " + accessToken.token);

    // Make the request to the Play Integrity API
    const response = await axios.post(url, {
      integrity_token: integrityToken
    }, {
      headers: {
        'Authorization': `Bearer ${accessToken.token}`, // Use the retrieved access token
        'Content-Type': 'application/json',
      },
    });

    // Handle the response
    console.log("Integrity token verified:", response.data);
    return response.data.tokenPayloadBasic;

  } catch (error) {
    console.error("Error during integrity token verification:", error.response ? error.response.data : error.message);
    throw error; // Rethrow the error for handling in the endpoint
  }
}

// Endpoint to verify integrity token
app.post('/verify-integrity', async (req, res) => {
  const { integrityToken } = req.body;
  console.log("Received request on /verify-integrity");  // Log request

  if (!integrityToken) {
    console.log("Error: Missing integrity token");
    return res.status(400).json({ error: 'Missing integrity token' });
  }

  console.log("Received Integrity Token: ", integrityToken);  // Log the token

  try {
    const payload = await verifyIntegrityToken(integrityToken); // Call the verification function
    console.log("Play Integrity API Response: ", payload);

    // Check device integrity
    const deviceIntegrity = payload.deviceIntegrity;
    const appIntegrity = payload.appIntegrity;

    if (deviceIntegrity.includes('MEETS_DEVICE_INTEGRITY')) {
      // The device passes the device integrity check (i.e., no rooting)
      console.log("Device Integrity passed");

      // Check app integrity
      if (appIntegrity.includes('PLAY_RECOGNIZED')) {
        console.log("App Integrity passed");
        return res.json({ success: true, message: 'Device and App passed integrity checks.' });
      } else {
        console.log("App Integrity failed: APK tampered with.");
        return res.status(403).json({ success: false, message: 'App integrity check failed (APK tampered).' });
      }
    } else {
      console.log("Device Integrity failed: Root detected.");
      return res.status(403).json({ success: false, message: 'Device integrity compromised (rooted).' });
    }
  } catch (error) {
    console.error("Error reading verification payload: ", error.message);
    return res.status(500).json({ error: error.message });
  }
});

const port = 3000;
app.listen(port, () => {
  console.log(`Backend running on http://localhost:${port}`);
});
