
SMR-MAY-2018
Samsung Mobile is releasing a maintenance release for major flagship models as part of monthly Security Maintenance Release (SMR) process. This SMR package includes patches from Google and Samsung.


Google patches include patches up to Android Security Bulletin - May 2018 package; and Android security patch level (SPL) of May 1, 2018 includes all of these patches. The Bulletin (May 2018) contains the following CVE items:

Critical	
CVE-2017-13292, CVE-2017-18071, CVE-2017-18146, CVE-2017-18128, CVE-2018-3592, CVE-2018-3591

High	
CVE-2017-5754, CVE-2018-3566, CVE-2018-3563, CVE-2017-18074, CVE-2017-18135, CVE-2017-18138, CVE-2017-18129, CVE-2017-18132, CVE-2017-18133, CVE-2017-18147, CVE-2017-18143, CVE-2018-3589, CVE-2017-13309(O8.1), CVE-2017-13310(M6.x, N7.x, O8.x), CVE-2017-13311(N7.x, O8.x), CVE-2017-13312(O8.0), CVE-2017-13313(M6.x, N7.x, O8.x), CVE-2017-13314(N7.x, O8.x), CVE-2017-13315(M6.x, N7.x, O8.x), CVE-2017-13319(M6.x), CVE-2017-13320(M6.x)

Moderate	
CVE-2017-13166, CVE-2017-14896, CVE-2017-13305, CVE-2017-17449, CVE-2017-13307, CVE-2017-17712, CVE-2017-15115, CVE-2018-3598, CVE-2018-3584, CVE-2017-8269, CVE-2017-15837, CVE-2018-5825, CVE-2018-5822, CVE-2018-5821, CVE-2018-5820, CVE-2018-3599, CVE-2018-5828, CVE-2017-14890, CVE-2017-14880, CVE-2017-11075, CVE-2017-13295(M6.x, N7.x, O8.x), CVE-2017-13316(M6.x, N7.x, O8.x), CVE-2017-13317(O8.1), CVE-2017-13318(O8.1), CVE-2017-13319(N7.x, O8.x), CVE-2017-13320(N7.x, O8.x), CVE-2017-13323(M6.x, N7.x, O8.x), CVE-2017-13321(O8.x)

Low	
None

NSI	
None

Already included in previous updates	
CVE-2017-1653, CVE-2017-13077, CVE-2017-17770, CVE-2017-15822, CVE-2017-8274, CVE-2017-18073, CVE-2017-18125, CVE-2017-18137, CVE-2017-18134, CVE-2018-3594, CVE-2018-5826, CVE-2017-15853, CVE-2018-5823, CVE-2018-3596, CVE-2018-3567, CVE-2017-15855, CVE-2017-15836, CVE-2017-14894

Not applicable to Samsung devices	
CVE-2017-13161, CVE-2017-13213, CVE-2017-13221, CVE-2017-13270, CVE-2017-13271, CVE-2017-13293, CVE-2017-8275, CVE-2017-11011, CVE-2017-18136, CVE-2017-18140, CVE-2017-18142, CVE-2017-18139, CVE-2017-18072, CVE-2017-18126, CVE-2017-18144, CVE-2017-18145, CVE-2017-18130, CVE-2017-18127, CVE-2018-3590, CVE-2018-3593, CVE-2017-13303, CVE-2017-13304, CVE-2017-13306


※ Please see Android Security Bulletin for detailed information on Google patches.	


Along with Google patches, Samsung Mobile provides 7 Samsung Vulnerabilities and Exposures (SVE) items described below, in order to improve our customer’s confidence on security of Samsung Mobile devices. Samsung security index (SSI), found in “Security software version”, SMR May-2018 Release 1 includes all patches from Samsung and Google. Some of the SVE items may not be included in this package, in case these items were already included in a previous maintenance release.


SVE-2018-11552: Bootloader not to check an integrity of specially system image	

Severity: High
Affected versions: N(7.x), O(8.0) devices with MSM8998 and SDM845 chipset
Reported on: February 24, 2018
Disclosure status: Publicly disclosed.
There was a vulnerability within the verification of Qualcomm MSM8998 and SDM845 bootloader and it may allow an attacker to bypass secure boot given the attacker gains root privilege.
The patch has been applied to properly check the integrity of system image.


SVE-2018-11633: Theft of arbitrary files leading to emails and email accounts takeover	

Severity: Moderate
Affected versions: M(6.0)
Reported on: February 11, 2018
Disclosure status: Privately disclosed.
This vulnerability allows an attacker to gain information of email by calling unprotected intent.
The patch sanitized files not to expose email information.


SVE-2018-11358: Out of Bounds access vulnerability in kernel driver	

Severity: Low
Affected versions: M(6.0), N(7.x), O(8.0) devices with Exynos chipset
Reported on: February 19, 2018
Disclosure status: Privately disclosed.
Assuming root privilege is achieved, this vulnerability allows an attacker to gain an Out Of Bounds Read/Write leading to possible arbitrary code execution.
The patch removed the part of code related to Out Of Bounds access.


SVE-2018-11599: Buffer Overflow in Trustlet	

Severity: Critical
Affected versions: O(8.0) devices with Exynos chipset
Reported on: March 20, 2018
Disclosure status: Privately disclosed.
Buffer overflow vulnerability exist in trustlet.
The patch prevented a buffer overflow by using a verified size.


SVE-2018-11600: Information disclosure on Trustlet	

Severity: Moderate
Affected versions: O(8.0)
Reported on: March 20, 2018
Disclosure status: Privately disclosed.
The address information of trustlet is logged.
The patch deleted all logs related to address information of trustlet.


SVE-2017-10748: Accessing the Clipboard content using Edge panel(Clipboard Edge) without unlocking the Phone	

Severity: High
Affected versions: N(7.x), O (8.0) (Galaxy S9+, Galaxy S9, Galaxy S8+, Galaxy S8, Note 8)
Reported on: October 27, 2017
Disclosure status: Privately disclosed.
The clipboard edge content can be leaked with attackers without any of user authentication.
The patch adds protection to hide clipboard contents immediately when device is locked.

Some SVE items included in the Samsung Android Security Update cannot be disclosed at this time.	


Acknowledgements

We truly appreciate the following researchers for helping Samsung to improve the security of our products. 

- Chang Uk Chung: SVE-2018-11599, SVE-2018-11600
- Toshin Sergey: SVE-2018-11633
- National Cyber Security Centre: SVE-2018-11358
- Vijay Balaganesan: SVE-2017-10748


SMR-JUN-2018
Samsung Mobile is releasing a maintenance release for major flagship models as part of monthly Security Maintenance Release (SMR) process. This SMR package includes patches from Google and Samsung.


Google patches include patches up to Android Security Bulletin - June 2018 package; and Android security patch level (SPL) of June 1, 2018 includes all of these patches. The Bulletin (June 2018) contains the following CVE items:	

Critical	
CVE-2018-3580, CVE-2018-9341, CVE-2018-5146, CVE-2018-9355, CVE-2018-9356

High	
CVE-2017-13225, CVE-2017-16643, CVE-2018-5841, CVE-2018-5850, CVE-2017-18154, CVE-2018-3562, CVE-2018-9338, CVE-2018-9339, CVE-2017-13227, CVE-2018-9340, CVE-2018-9344, CVE-2018-9345, CVE-2018-9346, CVE-2018-9347, CVE-2018-9348, CVE-2018-9357, CVE-2018-9358, CVE-2018-9359, CVE-2018-9360, CVE-2018-9361, CVE-2018-9362, CVE-2018-9349(6.x), CVE-2018-9350(6.x), CVE-2018-9351(6.x), CVE-2018-9352(6.x), CVE-2018-9353(6.x), CVE-2018-9354(6.x)

Moderate	
CVE-2017-15852, CVE-2018-5824, CVE-2017-8269, CVE-2018-5344, CVE-2017-15129, CVE-2018-5849, CVE-2018-5851, CVE-2018-5842, CVE-2018-5853, CVE-2018-5843, CVE-2018-3582, CVE-2018-3581, CVE-2018-3576, CVE-2018-3572, CVE-2018-3571, CVE-2017-18153, CVE-2017-15854, CVE-2017-15843, CVE-2017-15842, CVE-2017-15832, CVE-2017-0622, CVE-2018-5852, CVE-2018-9374, CVE-2018-9375, CVE-2018-9378, CVE-2018-9379, CVE-2018-9380, CVE-2018-9381, CVE-2018-9382, CVE-2018-9349(7.x, 8.x), CVE-2018-9350(7.x, 8.x), CVE-2018-9351(7.x, 8.x), CVE-2018-9352(7.x, 8.x), CVE-2018-9353(7.x, 8.x)

Low	
None

NSI	
CVE-2018-9354(7.x, 8.x)

Already included in previous updates	
CVE-2018-5846, CVE-2018-5845, CVE-2018-3578, CVE-2018-3565, CVE-2017-13077, CVE-2018-5844, CVE-2018-5847, CVE-2018-3579

Not applicable to Samsung devices	
CVE-2017-6289, CVE-2017-6293, CVE-2017-5715, CVE-2018-5840, CVE-2018-6254, CVE-2018-6246, CVE-2018-5848, CVE-2017-18070, CVE-2017-13230


※ Please see Android Security Bulletin for detailed information on Google patches.	


Along with Google patches, Samsung Mobile provides 3 Samsung Vulnerabilities and Exposures (SVE) items described below, in order to improve our customer’s confidence on security of Samsung Mobile devices. Samsung security index (SSI), found in “Security software version”, SMR Jun-2018 Release 1 includes all patches from Samsung and Google. Some of the SVE items may not be included in this package, in case these items were already included in a previous maintenance release.


SVE-2018-11599: Buffer overflow in Trustlet	

Severity: Critical
Affected Versions: N(7.X) devices with Exynos or MediaTek chipset
Reported on: March 20, 2018
Disclosure status: Privately disclosed.
Lack of boundary checking of a buffer in trustlet can lead to memory corruption.
The supplied patch prevents buffer overflow by confirming the sizes of source and destination.


SVE-2018-11600: Information disclosure in Trustlet	

Severity: Moderate
Affected Versions: N(7.X)
Reported on: March 20, 2018
Disclosure status: Privately disclosed.
The vulnerability exposes the address information of Trustlet in the log.
The patch removes the problematic code.


SVE-2018-11792: Keymaster architecture vulnerability	

Severity: Critical
Affected Versions: M(6.0), N(7.x), O(8.0) devices with Exynos chipset
Reported on: February 12, 2018
Disclosure status: Privately disclosed.
One of tlApi was not protected from unspecific trustlet.
The patch restricts access of tlApi in TEE via access control mechanism.

Some SVE items included in the Samsung Android Security Update cannot be disclosed at this time.	


Acknowledgements

We truly appreciate the following researchers for helping Samsung to improve the security of our products. 

- Chang Uk Chung: SVE-2018-11599, SVE-2018-11600
- Ben Lapid and Avishai Wool: SVE-2018-11792 


SMR-JUL-2018
Samsung Mobile is releasing a maintenance release for major flagship models as part of monthly Security Maintenance Release (SMR) process. This SMR package includes patches from Google and Samsung.


Google patches include patches up to Android Security Bulletin - July 2018 package; and Android security patch level (SPL) of July 1, 2018 includes all of these patches. The Bulletin (July 2018) contains the following CVE items:	

Critical	
CVE-2018-9373, CVE-2018-9433, CVE-2018-9411, CVE-2018-9365

High	
CVE-2017-0564, CVE-2017-13077, CVE-2018-5896, CVE-2018-9368, CVE-2017-17807, CVE-2017-17558, CVE-2017-17806, CVE-2018-9367, CVE-2018-5829, CVE-2018-5831, CVE-2018-9410, CVE-2018-9424, CVE-2018-9428, CVE-2018-9412, CVE-2018-9421, CVE-2018-9432, CVE-2018-9420, CVE-2018-9419, CVE-2018-9423(6.x), CVE-2018-5383

Moderate	
CVE-2018-5827, CVE-2018-3568, CVE-2017-15857, CVE-2018-5857, CVE-2018-9389, CVE-2018-5832, CVE-2018-5895, CVE-2018-9401, CVE-2018-5897, CVE-2017-13308, CVE-2018-5898, CVE-2018-5889, CVE-2018-5890, CVE-2018-9398, CVE-2016-5342, CVE-2016-5080, CVE-2017-11088, CVE-2017-15856, CVE-2018-3564, CVE-2017-18075, CVE-2018-9383, CVE-2018-9385, CVE-2018-5836, CVE-2018-7480, CVE-2018-9377, CVE-2018-9426, CVE-2018-9429, CVE-2018-9423(7.x, 8.x), CVE-2018-9413, CVE-2018-9418, CVE-2018-9430, CVE-2018-9414, CVE-2018-9431

Low	
None

NSI	
None

Already included in previous updates	
CVE-2017-18155, CVE-2018-5885, CVE-2018-5892, CVE-2018-5830, CVE-2018-5834, CVE-2018-3597

Not applicable to Samsung devices	
CVE-2018-9363, CVE-2017-18158, CVE-2017-18158, CVE-2017-18159, CVE-2018-9364, CVE-2017-6294, CVE-2017-6292, CVE-2017-6290, CVE-2018-9369, CVE-2018-9370, CVE-2018-9371, CVE-2018-9372, CVE-2018-5854, CVE-2018-9366, CVE-2018-5891, CVE-2017-18156, CVE-2017-18157, CVE-2018-5884, CVE-2018-5894, CVE-2018-5835, CVE-2018-3569, CVE-2017-11076, CVE-2017-15824, CVE-2018-9388, CVE-2017-14872, CVE-2017-14893, CVE-2017-15824, CVE-2018-9407, CVE-2018-9408, CVE-2018-9386, CVE-2018-5887, CVE-2018-5888, CVE-2018-5899, CVE-2018-9400, CVE-2018-9396, CVE-2018-9392, CVE-2018-9391, CVE-2018-9403, CVE-2018-9404, CVE-2018-3577, CVE-2018-9409


※ Please see Android Security Bulletin for detailed information on Google patches.	


Along with Google patches, Samsung Mobile provides 9 Samsung Vulnerabilities and Exposures (SVE) items described below, in order to improve our customer’s confidence on security of Samsung Mobile devices. Samsung security index (SSI), found in “Security software version”, SMR Jul-2018 Release 1 includes all patches from Samsung and Google. Some of the SVE items may not be included in this package, in case these items were already included in a previous maintenance release.


SVE-2018-11599: Buffer overflow in Trustlet	

Severity: Critical
Affected Versions: M(6.0) devices with Exynos or MediaTek chipset
Reported on: March 20, 2018
Disclosure status: Privately disclosed.
Lack of boundary checking of a buffer in Trustlet can lead to memory corruption.
The patch prevents buffer overflow by confirming the size of source and destination.


SVE-2018-11600: Information disclosure in Trustlet	

Severity: Moderate
Affected Versions: M(6.0)
Reported on: March 20, 2018
Disclosure status: Privately disclosed.
The vulnerability exposes the address information of Trustlet in the log.
The patch removes the problematic code.


SVE-2018-11669: Secure folder split screen bug	

Severity: Moderate
Affected Versions: O(8.0)
Reported on: April 4, 2018
Disclosure status: Privately disclosed.
A vulnerability allows execution of application in Secure Folder without password.
The patch prevents showing of applications of Secure Folder in split screen when Secure Folder is locked.


SVE-2018-11852: Kernel information disclosure vulnerability in Mediatek driver function	

Severity: Low
Affected Versions: N(7.x) devices with Mediatek chipsets
Reported on: September 08, 2017
Disclosure status: Privately disclosed.
The vulnerability allows an attacker to use an exposed kernel stack value for future attack scenarios.
The patch prevent the kernel stack value from exposure by initializing variables.

Some SVE items included in the Samsung Android Security Update cannot be disclosed at this time.	


Acknowledgements

We truly appreciate the following researchers for helping Samsung to improve the security of our products. 

- Chang Uk Chung: SVE-2018-11599, SVE-2018-11600
- Suthiwat: SVE-2018-11669
- Frederic Basse: SVE-2018-11852


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


SMR-SEP-2018

Samsung Mobile is releasing a maintenance release for major flagship models as part of monthly Security Maintenance Release (SMR) process. This SMR package includes patches from Google and Samsung.


Google patches include patches up to Android Security Bulletin – Sep 2018 package. The Bulletin (Sep 2018) contains the following CVE items:	

Critical  
CVE-2017-18310, CVE-2017-18305, CVE-2017-18296, CVE-2017-15817, CVE-2018-9475, CVE-2018-9478, CVE-2018-9479, CVE-2018-9411, CVE-2018-9427 

High  
CVE-2018-11258, CVE-2018-9465, CVE-2018-11260, CVE-2017-18308, CVE-2017-18301, CVE-2017-18302, CVE-2017-18300, CVE-2017-18304, CVE-2017-18298, CVE-2017-18297, CVE-2017-18293, CVE-2017-18295, CVE-2017-18303, CVE-2017-18299, CVE-2017-18282, CVE-2017-18280, CVE-2018-5383, CVE-2018-9466, CVE-2018-9467, CVE-2018-9468, CVE-2018-9469, CVE-2018-9470, CVE-2018-9471, CVE-2018-9472, CVE-2018-9474, CVE-2018-9440, CVE-2018-9456, CVE-2018-9477, CVE-2018-9480, CVE-2018-9481, CVE-2018-9482, CVE-2018-9483, CVE-2018-9484, CVE-2018-9485, CVE-2018-9486, CVE-2018-9487 

Moderate  
CVE-2017-15814, CVE-2017-15851, CVE-2017-8261, CVE-2017-9711, CVE-2018-3587, CVE-2017-18307, CVE-2017-18306, CVE-2018-1068, CVE-2018-9439, CVE-2018-5904, CVE-2018-5905, CVE-2018-5909, CVE-2018-5903, CVE-2018-5910, CVE-2018-11263, CVE-2018-5908, CVE-2017-13322, CVE-2017-13295, CVE-2018-9488 

Low	
None

NSI	
None

Already included in previous updates  
CVE-2017-18309, CVE-2017-18294, CVE-2017-18292, CVE-2017-18281, CVE-2017-13077 

Not applicable to Samsung devices  
CVE-2018-9406, CVE-2018-11305, CVE-2017-18283, CVE-2017-18249, CVE-2018-9464, CVE-2018-9463, CVE-2018-9462

※ Please see Android Security Bulletin for detailed information on Google patches.	


Along with Google patches, Samsung Mobile provides 18 Samsung Vulnerabilities and Exposures (SVE) items described below, in order to improve our customer’s confidence on security of Samsung Mobile devices. Samsung security index (SSI), found in “Security software version”, SMR Sep-2018 Release 1 includes all patches from Samsung and Google. Some of the SVE items may not be included in this package, in case these items were already included in a previous maintenance release. 


SVE-2017-11857: Buffer overflow vulnerability in ecryptfs

Severity: Low
Affected versions: M(6.0) N(7.x) O(8.x) except exynos9610/9820 in all Platforms, M(6.0) except MSM8909 SC77xx/9830 exynos3470/5420, N(7.0) except MSM8939, N(7.1) except MSM8996 SDM6xx/M6737T
Reported on: Sep 11, 2017
Disclosure status: Privately disclosed.
The vulnerability allows an attacker to cause an integer underflow.
The patch inserts logic to check the size of the variable to prevent integer underflow.


SVE-2018-11940: Rooting of device with custom image

Severity: High
Affected versions: N(7.0) devices with Qualcomm models using MSM8996 chipset
Reported on: May 12, 2017
Disclosure status: Privately disclosed.
The vulnerability allows an attacker to use a specially modified image to run scripts in INIT context.
The patch deleted all unnecessary execution commands in INIT.


SVE-2018-12053: QuickTools vulnerability

Severity: Moderate
Affected versions: O(8.x) S9 series, S8 series, S7 sereise, S6 series, Note FE, Note 8, Note 5
Reported on: May 25, 2018
Disclosure status: Privately disclosed.
The vulnerability allows location permission to bypass lockscreen when using the compass function in QuickTools.
The patch checks the lock state and allows permission.


SVE-2018-12458: Smartwatch Displaying Secure Folder Notification Contents

Severity: High
Affected versions: O(8.x)
Reported on: July 09, 2018
Disclosure status: Privately disclosed.
The vulnerability allows hidden content notifications of Secure Folder to be displayed in smartwatch.
The patches blocks notifications to smartwatches coming from Secure Folder.


SVE-2018-12757: Stack buffer overflow in Shannon Baseband

Severity: Critical
Affected versions: N(7.x) O(8.x) P(9.0) devices with Exynos chipset
Reported on: July 05, 2018
Disclosure status: Privately disclosed.
Stack buffer overflow vulnerability in Shannon Baseband components.
The applied patch adds check of length range to prevent buffer overflow.


SVE-2018-12761: Cache-attacks on AES-GCM implementation

Severity: Moderate
Affected versions: N(7.0) devices with Exynos exynos7420 chipset and O(8.0) devices with Exynos 8890/8996 chipset
Reported on: June 25, 2018
Disclosure status: Privately disclosed.
In Keymaster, AES implementations based on T-Tables are vulnerable and slow in comparison to CE(Cryptography Extension) instruction.
Keymaster is updated to use AES implementations based on CE(Cryptography Extension) instead of T-Tables, to enhance security and performance.


SVE-2018-11806: Clipboard contents visible when device is locked

Severity: Moderate
Affected versions: N(7.x) O(8.x)
Reported on: April 30, 2018
Disclosure status: Privately disclosed.
Clipboard was not disabled for emergency contact picker while the device is locked.
The patch disabled the clipboard for emergency contact picker while the phone is locked.


SVE-2018-11989, SVE-2018-11990: Keyboard learned words leak when device is locked

Severity: Moderate
Affected versions: N(7.x) O(8.x)
Reported on: May 17, 2018
Disclosure status: Privately disclosed.
Prediction clipboard was not disabled for emergency contact picker while the device is locked.
The patch disabled the prediction clipboard for emergency contact picker while the phone is locked.



Some SVE items included in the Samsung Android Security Update cannot be disclosed at this time. 

Acknowledgements

We truly appreciate the following researchers for helping Samsung to improve the security of our products. 

- Frédéric Basse : SVE-2017-11857
- Andr Ess : SVE-2018-11806
- Bogdan : SVE-2018-11989, SVE-2018-11990, SVE-2018-12053
- Thomas Huntington : SVE-2018-11940
- Ovidiu Sirb : SVE-2018-12458
- Ben Lapid and Avishai Wool : SVE-2018-12761





SMR-OCT-2018
Samsung Mobile is releasing a maintenance release for major flagship models as part of monthly Security Maintenance Release (SMR) process. This SMR package includes patches from Google and Samsung.


Google patches include patches up to Android Security Bulletin - Oct 2018 package. The Bulletin (Oct 2018) contains the following CVE items:	

Critical	
CVE-2016-10394, CVE-2018-11950, CVE-2018-5866, CVE-2018-11824, CVE-2018-9490, CVE-2018-9473, CVE-2018-9496, CVE-2018-9497, CVE-2018-9498, CVE-2017-13283, CVE-2018-9476, CVE-2018-9504

High	
CVE-2017-5754, CVE-2018-11816, CVE-2018-11898, CVE-2018-11842, CVE-2018-11836, CVE-2018-11261, CVE-2016-10408, CVE-2017-18313, CVE-2017-18312, CVE-2017-18124, CVE-2018-3588, CVE-2018-11951, CVE-2018-11952, CVE-2018-5871, CVE-2018-5914, CVE-2018-11288, CVE-2018-11292, CVE-2018-11846, CVE-2018-9491, CVE-2018-9492, CVE-2018-9493, CVE-2018-9499, CVE-2018-9501, CVE-2018-9502, CVE-2018-9503, CVE-2018-9505, CVE-2018-9506, CVE-2018-9507, CVE-2018-9508, CVE-2018-9509, CVE-2018-9510, CVE-2018-9511

Moderate	
CVE-2018-5832, CVE-2018-11270, CVE-2018-9452, CVE-2018-5390, CVE-2018-5391

Low	
None

NSI	
None

Already included in previous updates	
CVE-2018-9384, CVE-2017-18314, CVE-2017-18311, CVE-2018-11290, CVE-2018-11287, CVE-2018-11855

Not applicable to Samsung devices	
CVE-2017-15825, CVE-2018-11285, CVE-2018-11857, CVE-2018-11858, CVE-2018-11866, CVE-2018-11865


※ Please see Android Security Bulletin for detailed information on Google patches.	


Along with Google patches, Samsung Mobile provides 11 Samsung Vulnerabilities and Exposures (SVE) items described below, in order to improve our customer’s confidence on security of Samsung Mobile devices. Samsung security index (SSI), found in “Security software version”, SMR Oct-2018 Release 1 includes all patches from Samsung and Google. Some of the SVE items may not be included in this package, in case these items were already included in a previous maintenance release.


SVE-2018-12852: Buffer overflow in the Trustlet	

Severity: Critical
Affected Versions: N(7.x), O(8.X) devices with Exynos chipsets
Reported on: August 15, 2018
Disclosure status: Privately disclosed.
A buffer overflow vulnerability in esecomm trustlet allows an attacker to perform arbitrary code execution.
The patch adds proper validation of buffer length to prevent buffer overflow.


SVE-2018-12853: Invalid free in the Trustlet	

Severity: Critical
Affected Versions: N(7.x), O(8.x) devices with Exynos chipsets
Reported on: August 15, 2018
Disclosure status: Privately disclosed.
An invalid free vulnerability in fingerprint trustlet allows an attacker to perform arbitrary code execution.
The patches deallocate the right pointer to prevent invalid free.


SVE-2018-12855: Incorrect usage of shared memory in the Trustlet	

Severity: Critical
Affected Versions: N(7.x), O(8.X) devices with Exynos chipsets
Reported on: August 15, 2018
Disclosure status: Privately disclosed.
A vulnerability in vaultkeeper trustlet leaks shared memory address allowing an attacker to perform arbitrary code execution.
The patch adds proper validation of shared memory address.


SVE-2018-12684: Clipoboard access in lockscreen	

Severity: Moderate
Affected Versions: N(7.x), O(8.x), P(9.0)
Reported on: July 26, 2018
Disclosure status: Privately disclosed.
The clipboard content can be leaked without authorization when using physical keyboard.
The patch adds protection to hide clipboard contents immediately when device is locked.

Some SVE items included in the Samsung Android Security Update cannot be disclosed at this time.	


Acknowledgements

We truly appreciate the following researchers for helping Samsung to improve the security of our products.

- Eloi Sanfelix: SVE-2018-12852, SVE-2018-12853, SVE-2018-12855
- Andr. Heß: SVE-2018-12684


