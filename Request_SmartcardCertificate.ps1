Function Request_SmartcardCertificate {
    <#
     .SYNOPSIS
     Function to request a smartcard certificate from the "<Your Template>" template.
     
     .NOTES
     Author: Charles Hamby
     Revised by:
     Date: 6/27/2022
     -Requires a user variable for the recipient of the smartcard certificate.
     -Requires an Administrator signer key and certificate with EKU "1.3.6.1.4.1.311.20.2.1"

     .EXAMPLE
     Request_SmartcardCertificate -Requester "User" -Domain "Domain"
    #>
    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $false)]
        [String]$Requester = "",
	      [Parameter(Mandatory = $true, ValueFromPipeline = $false)]
        [String]$Domain = ""
    );

    # Create new PKCS#10 Object
    $PKCS10 = New-Object -ComObject X509Enrollment.CX509CertificateRequestPkcs10;
    
    # Initialize the request object using the smartcard certificate template info
    $PKCS10.InitializeFromTemplateName(0x1,"SmartcardLogon");
    
    # Generate the key pair and sign the PKCS#10 File
    $PKCS10.Encode();
    
    # Create new PKCS#7 Object
    $pkcs7 = New-Object -ComObject X509enrollment.CX509CertificateRequestPkcs7;
    
    # Wrap PKCS#10 signed object in PKCS#7 Object
    $pkcs7.InitializeFromInnerRequest($pkcs10);
    
    #Set user variable for requestor
    $pkcs7.RequesterName = "$Domain\$requester";
    
    # Create Admin certificate Signer object
    $signer = New-Object -ComObject X509Enrollment.CSignerCertificate;
    
    # Select available signer certificates from User Cert Store based on the OID used for Enrollment Agents
    $cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object {$_.Extensions | Where-Object {$_.Oid.Value -eq "2.5.29.37" -and $_.EnhancedKeyUsages["1.3.6.1.4.1.311.20.2.1"]}};
    
    # Convert the certificate details to Base64 encoding required for the CSignerCertificate object to initialize
    $Base64 = [Convert]::ToBase64String($Cert.RawData);
    
    # Initialize Signer Object with the Enrollment Agent Certificate
    $signer = New-Object -ComObject X509Enrollment.CSignerCertificate;
    Read-Host "Enrollment Agent Certificate Required - Please plug in signer Yubikey now, then press Enter to continue..."
    $signer.Initialize(0,0,1,$Base64);
    
    # Add the Signer Object as the SignerCertificate Property for PKCS#7 Object
    $pkcs7.SignerCertificate = $signer;
    
    # Create the New Enrollment Request and Initialize
    $Request = New-Object -ComObject X509Enrollment.CX509Enrollment;
    $Request.InitializeFromRequest($pkcs7);
    
    # Notify Admin to watch for Yubikey Blink to touch metal leads
    Write-Host "Prepare to enter your PIN. Once entered, when the Yubikey slowly blinks, touch the metal leads to sign the certificate." -ForegroundColor Magenta;
    
    # Try enrollment
    Try {
        
        # Submit Enrollment Request
        $Request.Enroll();
    
    }Catch {
    
        Write-Host "Could not generate Certificate" -ForegroundColor Red;
        Break;
    
    };
};
