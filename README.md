
SMR-AUG-2018
Samsung Mobile is releasing a maintenance release for major flagship models as part of monthly Security Maintenance Release (SMR) process. This SMR package includes patches from Google and Samsung.


Google patches include patches up to Android Security Bulletin – Aug 2018 package. The Bulletin (Aug 2018) contains the following CVE items:	

Critical	
CVE-2018-11257, CVE-2018-9427, CVE-2018-9446, CVE-2018-9450

High	
CVE-2017-18131, CVE-2018-5837, CVE-2018-9422, CVE-2018-9417, CVE-2018-6927, CVE-2018-5873, CVE-2017-18278, CVE-2017-18172, CVE-2017-18277, CVE-2017-18279, CVE-2018-9445, CVE-2018-9438, CVE-2018-9458, CVE-2018-9451, CVE-2018-9444, CVE-2018-9437(M6.x), CVE-2018-9455, CVE-2018-9436, CVE-2018-9454, CVE-2018-9448, CVE-2018-9453

Moderate	
CVE-2018-9402, CVE-2018-9397, CVE-2018-9395, CVE-2018-9394, CVE-2018-9393, CVE-2018-5893, CVE-2018-9390, CVE-2017-0606, CVE-2017-1000, CVE-2018-9415, CVE-2018-3570, CVE-2018-9416, CVE-2018-1065, CVE-2018-5859, CVE-2018-5862, CVE-2018-5865, CVE-2018-5858, CVE-2018-5864, CVE-2018-9376, CVE-2018-9437(N7.x, O8.x), CVE-2017-1000100, CVE-2018-9435, CVE-2018-9449, CVE-2018-9441, CVE-2018-9447

Low	
None

NSI	
None

Already included in previous updates	
CVE-2018-5838, CVE-2016-2108, CVE-2017-15841, CVE-2017-18276, CVE-2017-13077, CVE-2017-13078

Not applicable to Samsung devices	
CVE-2018-3586, CVE-2018-11259, CVE-2018-5703, CVE-2018-5882, CVE-2018-5878, CVE-2018-5876, CVE-2018-5874, CVE-2018-5875, CVE-2018-5872, CVE-2017-18173, CVE-2017-18170, CVE-2017-18171, CVE-2017-18274, CVE-2017-18275, CVE-2017-1821, CVE-2018-7995, CVE-2018-9459, CVE-2018-9461, CVE-2018-9457, CVE-2017-13242


※ Please see Android Security Bulletin for detailed information on Google patches.	


Along with Google patches, Samsung Mobile provides 11 Samsung Vulnerabilities and Exposures (SVE) items described below, in order to improve our customer’s confidence on security of Samsung Mobile devices. Samsung security index (SSI), found in “Security software version”, SMR Aug-2018 Release 1 includes all patches from Samsung and Google. Some of the SVE items may not be included in this package, in case these items were already included in a previous maintenance release.


SVE-2016-6341: Security attack scenario while fake charging at public kiosk  

Severity: High
Affected Versions: N(7.1), O(8.x)
Reported on: June 12, 2018
Disclosure status: Privately disclosed.
The vulnerability allows an attacker to execute critical functions without user interaction or any permissions even when devices are locked.
The patch restricts attacker from executing some critical functions while devices are locked.


SVE-2018-11766: Secure Folder Streams content without Biometrics Authenticated	

Severity: High
Affected Versions: N(7.x), O(8.x)
Reported on: April 17, 2018
Disclosure status: Privately disclosed.
When the device is connected to an external device, the gallery app in secure folder does not block the slideshow content even after secure folder is locked.
The patch is to hide the content on slideshow in gallery app to receive notification when the secure folder is locked.


SVE-2018-11792: Keymaster architecture vulnerability	

Severity: Critical
Affected Versions: M(6.0), N(7.x), O(8.x) devices with Exynos chipset
Reported on: February 12, 2018
Disclosure status: Privately disclosed.
One of tlApi was not protected from unspecific trustlet.
The patch restricts access control of tlApi in TEE via access control mechanism.


SVE-2017-11816: Array overflow vulnerability in drivers input booster	

Severity: Low
Affected Versions: N(7.x), O(8.x)
Reported on: November 07, 2017
Disclosure status: Privately disclosed.
The vulnerability allows an attacker to cause an array overflow.
The patch prevents array overflow by inserting logic to check the size of the index variable.


SVE-2018-11828: Buffer Overflow in Exynos Chipset	

Severity: Critical
Affected Versions: M(6.0), N(7.x), O(8.x) devices with Exynos chipset
Reported on: April 28, 2018
Disclosure status: Privately disclosed.
A buffer overflow vulnerability in a function of Exynos Chipset may result in baseband exploit.
The applied patch adds check of length range to prevent buffer overflow.


SVE-2017-11855: Integer underflow vulnerability in ecryptfs function	

Severity: Low
Affected Versions: M(6.0), N(7.x), O(8.x)
Reported on: Sep 11, 2017
Disclosure status: Privately disclosed.
The vulnerability allows an attacker to cause an integer underflow.
The patch prevent by inserting logic to check the size of the variable.


SVE-2018-12029: Buffer out of bounds write in WiFi Chip	

Severity: Low
Affected Versions: N(7.x) models with BCM4358 Chipset
Reported on: May 21, 2018
Disclosure status: Privately disclosed.
Lack of boundary checking of a buffer in WiFi Chip can lead to memory corruption.
The patch checks buffer size and prevents buffer overflow.

Some SVE items included in the Samsung Android Security Update cannot be disclosed at this time.	


Acknowledgements

We truly appreciate the following researchers for helping Samsung to improve the security of our products. 

- Rahul Koul: SVE-2018-11766
- Ben Lapid and Avishai Wool: SVE-2018-11792
- Yonggang Guo: SVE-2017-11816
- Frederic Basse: SVE-2017-11855
- Felicitas Hetzelt, Dokyung Song, Dipanjan Das: SVE-2018-12029


