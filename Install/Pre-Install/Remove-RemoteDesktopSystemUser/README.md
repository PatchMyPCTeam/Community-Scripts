# Remove Microsoft Remote Desktop Client Machine-wide and User installations

This script utilizes the PowerShell App Deployment Toolkit to uninstall ALL previous versions of Microsoft Remote Desktop Client found on a system. This includes all languages as well as User and Machine-Wide installs. (Note: the screenshot are for Webex, but the instructions remain the same)

Follow the Instructions below to add this script (and associated files) as a Prescript for the Patch My PC App or Update for Microsoft Remote Desktop Client.

1. Copy this entire folder to your Patch My PC Publisher Server
2. Open the Publisher and navigate to the tab for which you are deploying this update
3. Right Click on the "Remote Desktop" product and choose "Add custom pre/post scripts"
  ![image](https://github.com/PatchMyPCTeam/Community-Scripts/assets/3790176/80547626-f87e-4e92-ace3-5e151fdc37ec)

4. For Pre-Script click "Browse..." Navigate to the folder copied in Step 1 and choose "Deploy-Application.ps1"
  ![image](https://github.com/PatchMyPCTeam/Community-Scripts/assets/3790176/91bfbd26-f511-4d43-8687-fe9a20597817)

5. For "Addition files", click "Browse..." and choose all stand-alone files in the folder copied in Step 1
  ![image](https://github.com/PatchMyPCTeam/Community-Scripts/assets/3790176/b95a7c52-b897-4da8-a450-f30db476b675)

6. For "Additional folders" click "Browse..." and choose all folders in the folder copied in Step 1
  ![image](https://github.com/PatchMyPCTeam/Community-Scripts/assets/3790176/35d345f3-4f13-44f7-af94-b2ac90fffede)

7. When finished, everything should look like the screenshot below
  ![image](https://github.com/PatchMyPCTeam/Community-Scripts/assets/3790176/79253a95-be8e-4cc6-b11a-57b8a4edca3e)

8. Click OK
9. Right-click the product that you just modified and choose "Republish on Next Sync" (Additionally you can right click and choose to publish this product during the next manual sync)
  ![image](https://github.com/PatchMyPCTeam/Community-Scripts/assets/3790176/0e48e605-c83f-4641-ac61-cda8387026be)

10. Navigate to the "Sync Schedule" tab, and click "Run Publishing Service Sync"
  ![image](https://github.com/PatchMyPCTeam/Community-Scripts/assets/3790176/952d2bc1-1a69-44e9-9f37-0947219c6605)
