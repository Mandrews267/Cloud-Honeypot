# Honeypot Virtual Machine in Microsoft Azure and Monitoring for Failed Login Attempts and Locations where the Attempts Originate From.

The focus of this lab is to show familiarity with the Microsoft Azure cloud platform and creating rules and queries to monitor incoming attempts to gain entry into the system. I created a network infrastructure with a VM inside it that is open to all inbound communication, then captured the log generation from the VM into Azure using a Microsoft Sentinel instance. From there, I imported a data set that contains geographic information for each block of IP addresses. Along with creating a watchlist, this allows for the table of incoming failed login requests to be queried in a way where you can take the inbound IP address and parse the information to provide the geographic location in the search results.  

Finally, I created a heat map that takes the information from the saved query and maps out where attacks are originating from and the volume of those attacks. This was completed by creating a JSON file that includes a KQL query completing the following tasks:

- Retrieves the Geographic IP data from the imported dataset
- Filters Windows Security Events for failed logins (Event ID: 4625)
- Orders the results by time, with most recent first
- Performs an IP lookup
- Summarizes the data by grouping results of IP address, latitude, longitude, city, and country. Counts how many times each IP address failed to log in.
- Formats the output by renaming the fields for clarity and creating a "friendly location" string to list the geographic location in a city, country order.
- Visualizes the results in a heatmap mapping format.

## Technologies Used
- **Microsoft Azure**
- **Azure Network Security Group**
- **Microsoft Windows 10 VM setup**
- **Windows Defender Firewall with Advanced Security Console**
- **Azure Network Security Group rule generation**
- **Use of KQL queries**
- **JSON data structures**
- **Windows Event Viewer**

---

## Step 1: Create a "Try it Free" Microsoft Azure Account
1. To create a free Azure subscription, go to: [Azure Free Trial](https://azure.microsoft.com/en-us/pricing/purchase-options/azure-account)
2. After the subscription is created, log in at: [Azure Portal](https://portal.azure.com)

---

## Step 2: Create a Virtual Machine – The Honeypot
### Creating a Resource Group
1. From the Azure welcome screen, search for **Resource Groups** and select it.
2. Click **Create Resource Group** and enter a "Resource group name".
3. Click **Create**.

### Creating a Virtual Network
1. In the search bar, search for **Virtual Networks**.
2. Click **Create Virtual Network**.
3. Provide a **name** for the virtual network and ensure it is in the same **region** as the resource group.
4. Click **Review + Create** → **Create**.

### Creating the Virtual Machine
1. Search for **Virtual Machines** and select **Create Virtual Machine**.
2. Select the **Resource Group** created earlier.
3. Provide a **VM Name** (e.g., `CORP-NET-EAST-1`).
4. Select the **Windows 10 Pro** image.
5. Choose a **machine size** (free tier if applicable).
6. Set up **Administrator Username & Password**.
7. Click **Review + Create** → **Create**.

---

## Step 3: Configuring Network Security Rules
1. Navigate to **Network Security Group (NSG)**.
2. **Delete** the default **RDP inbound rule**.
3. **Create a new inbound rule** allowing all inbound traffic:
   - **Source:** Any
   - **Source Port Ranges:** `*`
   - **Destination:** Any
   - **Service:** Custom
   - **Destination Port Ranges:** `*`
   - **Protocol:** Any
   - **Action:** Allow
   - **Priority:** 100
   - **Name:** `DANGER_AllowAnyCustomAnyInbound`

> **⚠️ WARNING:** This makes the VM **completely open to attacks** for lab purposes.

---

## Step 4: Disabling Windows Firewall on the VM
1. Connect to the VM via **Remote Desktop**.
2. Open **Windows Defender Firewall** (`wf.msc`).
3. Set **Domain, Private, and Public Profiles** to **Off**.
4. Apply changes and confirm.

---

## Step 5: Viewing Raw Logs in Windows Event Viewer
1. Log into the VM and attempt incorrect logins multiple times.
2. Open **Event Viewer** → **Windows Logs → Security**.
3. Search for **Event ID 4625** (failed login attempts).

---

## Step 6: Forwarding Logs to Azure Sentinel
1. Create a **Log Analytics Workspace** and **Microsoft Sentinel Instance**.
2. Install **Windows Security Events** in Sentinel.
3. Create a **Data Collection Rule** to forward logs from the VM.

---

## Step 7: Uploading Geolocation Data to Sentinel
1. Download `geoip-summarized.csv`.
2. In **Microsoft Sentinel**, go to **Watchlists** and upload the file.

---

## Step 8: Querying Logs in KQL
```kql
let GeoIPDB_FULL = _GetWatchlist("geoip");
let WindowsEvents = SecurityEvent
| where EventID == 4625
| evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network);
WindowsEvents | project TimeGenerated, AttackerIp = IpAddress, cityname, countryname, latitude, longitude
```

---

## Step 9: Creating an Attack Heat Map
1. In **Microsoft Sentinel**, navigate to **Workbooks**.
2. Add a new workbook and insert the JSON configuration.
3. Save it as **Windows VM Attack Map**.

---

## Conclusion
This lab demonstrated how to:
- Set up a **honeypot VM**.
- Monitor **failed login attempts**.
- Enrich logs with **geolocation data**.
- Visualize attack sources with a **heat map**.
