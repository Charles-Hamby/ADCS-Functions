Function Parse-Certificate {
    <#

    .SYNOPSIS
    Parses an X.509 Certificate and creates a custom PSObject.

    .DESCRIPTION
    Using certutil, a custom PSObject is created with relevant cert details from a parsed certificate object.

    .EXAMPLE
    Parse-Certificate -CertPath C:\Temp\TestCert01.cer

    .NOTES
    Author: Charles Hamby
    Date: 3/20/2023
    Requires certutil
    

    .PARAMETER CertPath <String>
    Accept pipeline input?   true
    Aliases                  None

    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$CertPath = ""
    )


    ## Set default error action
    $ErrorActionPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue

        #Dump certificate details using certutil
        $certDump = certutil -v -dump $certPath | Out-String;

        ## Get Certificate Version
        $certVersion = (($certDump -split '\r?\n') | Where-Object {$_ -match "Version"}).Replace("Version:","").Trim();

        ## Get Certificate Serial number
        $certSerial = (($certDump -split '\r?\n') | Where-Object {$_ -match "Serial Number"}).Replace("Serial Number:","").Trim();
        
        ## Get Signature Algo and Sub-Attributes (Algorithm ObjectID & Algorithm Parameters:)
        $startpos = $certDump.IndexOf("Signature Algorithm:");
        $endpos = $CertDump.IndexOf("Issuer:");
        $subString = $certDump.Substring(0, $endPos);
        $finalString = $subString.Substring($startpos);
            
            ## Get Algorithm Object ID
            $signatureAlgorithm_AlgorithmObjectID = (($finalString -split '\r?\n') | Where-Object {$_ -match "Algorithm ObjectId:"}).Replace("Algorithm ObjectId:","").Trim();
        
            ## Get Algorithm Parameters
            $startpos = $finalstring.IndexOf("Algorithm Parameters");
            $signatureAlgorithm_AlgorithmParamters = $finalstring.Substring($startpos).Replace("Algorithm Parameters:","").Trim();
            
        ## Get Issuer Attributes
        $startpos = $certDump.IndexOf("Issuer:");
        $endpos = $CertDump.IndexOf("NotBefore:");
        $subString = $certDump.Substring(0, $endPos);
        $finalString = $subString.Substring($startpos)

            ## Get issuer Common Name if exist
            $issuerCN = (($finalString -split '\r?\n') | Where-Object {$_ -match "CN="}).Replace("CN=","").Trim();

            ## Get issuer OrgUnit if exist w multiple
            $issuerOUs = @((($finalString -split '\r?\n') | Where-Object {$_ -match "OU="}).Replace("OU=","").Trim());

            ## Get issuer Organization if exist w multiple
            $issuerOrgs = @((($finalString -split '\r?\n') | Where-Object {$_ -match "O="}).Replace("O=","").Trim());

            ## Get issuer Locality if exist w multiple
            $issuerLocality = @((($finalString -split '\r?\n') | Where-Object {$_ -match "L="}).Replace("L=","").Trim());

            ## Get issuer State if exist w multiple
            $issuerState = @((($finalString -split '\r?\n') | Where-Object {$_ -match "ST="}).Replace("ST=","").Trim());

            ## Get issuer Country if exist w multiple
            $issuerCountry = @((($finalString -split '\r?\n') | Where-Object {$_ -match "C="}).Replace("C=","").Trim());

            ## Get issuer Email if exist w multiple
            $issuerEmails = @();
            $Emails = @((($finalString -split '\r?\n') | Where-Object {$_ -match "E=" -or $_ -match "emailAddress=" }))
            foreach ( $email in $Emails ) {
                if ($email -match "E=") {
                    $issuerEmails += $email.Replace("E=","").Trim();

                }
                elseif ( $email -match "emailAddress=" ) {
                    $issuerEmails += $email.Replace("emailAddress=","").Trim();
                };
            };

            ## Get the Issuer Name Hash (SHA-1 & md5)
            $issuerNameHashSHA1 = (($finalString -split '\r?\n') | Where-Object { $_ -match "Name Hash"} | Where-Object {$_ -match "sha1"}).Replace("Name Hash(sha1):","").Trim();
            $issuerNameHashmd5 = (($finalString -split '\r?\n') | Where-Object { $_ -match "Name Hash"} | Where-Object {$_ -match "md5"}).Replace("Name Hash(md5):","").Trim();

        ## Get Certificate NotBefore Date
        $certNotBefore = [DateTime] (($certDump -split '\r?\n') | Where-Object {$_ -match "NotBefore:"}).Replace("NotBefore:","").Trim();
        $certNotBeforeGMT = [System.TimeZoneInfo]::ConvertTimeBySystemTimeZoneId($($certNotBefore), [System.TimeZoneInfo]::Local.Id, 'GMT Standard Time')
        
        ## Get Certificate NotAfter Date
        $certNotAfter = [DateTime] (($certDump -split '\r?\n') | Where-Object {$_ -match "NotAfter:"}).Replace("NotAfter:","").Trim();
        $certNotAfterGMT = [System.TimeZoneInfo]::ConvertTimeBySystemTimeZoneId($($certNotAfter), [System.TimeZoneInfo]::Local.Id, 'GMT Standard Time')

        ## Get SubjectAttributes
        $startpos = $certDump.IndexOf("Subject:");
        $endpos = $CertDump.IndexOf("Public Key Algorithm:");
        $subString = $certDump.Substring(0, $endPos);
        $finalString = $subString.Substring($startpos)

            ## Get subject Common Name if exist
            $subjectCN = (($finalString -split '\r?\n') | Where-Object {$_ -match "CN="}).Replace("CN=","").Trim();

            ## Get subject OrgUnit if exist w multiple
            $subjectOUs = @((($finalString -split '\r?\n') | Where-Object {$_ -match "OU="}).Replace("OU=","").Trim());

            ## Get subject Organization if exist w multiple
            $subjectOrgs = @((($finalString -split '\r?\n') | Where-Object {$_ -match "O="}).Replace("O=","").Trim());

            ## Get subject Locality if exist w multiple
            $subjectLocality = @((($finalString -split '\r?\n') | Where-Object {$_ -match "L="}).Replace("L=","").Trim());

            ## Get subject State if exist w multiple
            $subjectState = @((($finalString -split '\r?\n') | Where-Object {$_ -match "S="}).Replace("S=","").Trim());

            ## Get subject Country if exist w multiple
            $subjectCountry = @((($finalString -split '\r?\n') | Where-Object {$_ -match "C="}).Replace("C=","").Trim());

            ## Get subject Email if exist w multiple
            $subjectEmails = @();
            $Emails = @((($finalString -split '\r?\n') | Where-Object {$_ -match "E=" -or $_ -match "emailAddress=" }))
            foreach ( $email in $Emails ) {
                if ($email -match "E=") {
                    $subjectEmails += $email.Replace("E=","").Trim();

                }
                elseif ( $email -match "emailAddress=" ) {
                    $subjectEmails += $email.Replace("emailAddress=","").Trim();
                };
            };

            ## Get the Subject Name Hash (SHA-1 & md5)
            $issuerNameHashSHA1 = (($finalString -split '\r?\n') | Where-Object { $_ -match "Name Hash"} | Where-Object {$_ -match "sha1"}).Replace("Name Hash(sha1):","").Trim();
            $issuerNameHashmd5 = (($finalString -split '\r?\n') | Where-Object { $_ -match "Name Hash"} | Where-Object {$_ -match "md5"}).Replace("Name Hash(md5):","").Trim();

            ## Get Public Key Algo and Sub-Attributes (Algorithm ObjectID & Algorithm Parameters:)
            $startpos = $certDump.IndexOf("Public Key Algorithm:");
            $endpos = $CertDump.IndexOf("Public Key Length:");
            $subString = $certDump.Substring(0, $endPos);
            $finalString = $subString.Substring($startpos);

                ## Get Algorithm Object ID
                $publicKeyAlgorithm_AlgorithmObjectID = (($finalString -split '\r?\n') | Where-Object {$_ -match "Algorithm ObjectId:"}).Replace("Algorithm ObjectId:","").Trim();
        
                ## Get Algorithm Parameters
                $startpos = $finalstring.IndexOf("Algorithm Parameters");
                $publicKeyAlgorithm_AlgorithmParamters = $finalstring.Substring($startpos).Replace("Algorithm Parameters:","").Trim();

            ## Get Certificate Public Key Length:
            [int]$certPublicKeyLength = (($certDump -split '\r?\n') | Where-Object {$_ -match "Public Key Length:"}).Replace("Public Key Length:","").Replace("bits","").Trim();

        ## Get Certificate Extensions
        $startpos = $certDump.IndexOf("Certificate Extensions:");
        $endpos = $CertDump.IndexOf("Signature:");
        $subString = $certDump.Substring(0, $endPos);
        $finalString = $subString.Substring($startpos);
        
        ## Get the count of certificate extensions
        [int]$certExtensionsCount = (($certDump -split '\r?\n') | Where-Object {$_ -match "Certificate Extensions:"}).Replace("Certificate Extensions:","").Trim();

        ## Get Subject Key Identifier
        $subjectKeyIdentifierOID = "2.5.29.14";
        $startpos = $certDump.IndexOf("2.5.29.14:");
        $subString = $certDump.Substring($startpos);
        $endpos = $substring.IndexOf("0000");
        $finalString = $subString.Substring(0, $endpos);
        $startpos = $finalstring.IndexOf("Subject Key Identifier");
        $subjectKeyIdentifier = $finalstring.Substring($startpos).Replace("Subject Key Identifier","").Trim();

        ## Get Key Usage
        $KeyUsageOID = "2.5.29.15";
        $startpos = $certDump.IndexOf("2.5.29.15:");
        $subString = $certDump.Substring($startpos);
        $endpos = $substring.IndexOf("0000");
        $finalString = $subString.Substring(0, $endpos);
        $startpos = $finalstring.IndexOf("Key Usage");
        $KeyUsage = @($finalstring.Substring($startpos).Replace("Key Usage","").Trim()).Split(",").Trim().Split("(");
        $KeyUsage = @((($KeyUsage.Replace($($KeyUsage[-1]), "").Trim() | Where-Object {$_ -ne "" }) -split '\r?\n').Trim());

        ## Get Enhanced Key Usage
        $EnhancedKeyUsageOID = "2.5.29.37";
        $startpos = $certDump.IndexOf("2.5.29.37:");
        $subString = $certDump.Substring($startpos);
        $endpos = $substring.IndexOf("0000");
        $finalString = $subString.Substring(0, $endpos);
        $startpos = $finalstring.IndexOf("Enhanced Key Usage");
        $EnhancedKeyUsage = @((($finalstring.Substring($startpos).Replace("Enhanced Key Usage","").Replace("        ","").Trim()) -split '\r?\n').Trim());
        
        ## Get Authority Key Identifier
        $AuthorityKeyIdentifierOID = "2.5.29.35";
        $startpos = $certDump.IndexOf("2.5.29.35:");
        $subString = $certDump.Substring($startpos);
        $endpos = $substring.IndexOf("0000");
        $finalString = $subString.Substring(0, $endpos);
        $startpos = $finalstring.IndexOf("Authority Key Identifier");
        $AuthorityKeyIdentifier = $finalstring.Substring($startpos).Replace("Subject Key Identifier","").Trim().Replace("        KeyID=","").Trim();

        ## CRL Distribution Points
        $CRLDistributionPointOID = "2.5.29.31";
        $startpos = $certDump.IndexOf("2.5.29.31:");
        $subString = $certDump.Substring($startpos);
        $endpos = $substring.IndexOf("0000");
        $finalString = $subString.Substring(0, $endpos);
        $startpos = $finalstring.IndexOf("Full Name");
        $CRLDistributionPoint = (($finalstring.Substring($startpos).Replace("Full Name","").Trim()) -split '\r?\n').Trim().Replace("URL=","");

        ## Certificate Template Information
        $CertificateTemplateOID = "1.3.6.1.4.1.311.21.7";
        $startpos = $certDump.IndexOf("1.3.6.1.4.1.311.21.7:");
        $subString = $certDump.Substring($startpos);
        $endpos = $substring.IndexOf("0000");
        $finalString = $subString.Substring(0, $endpos);
        $startpos = $finalstring.IndexOf("Certificate Template Information");
        $CertificateTemplateInfo = ((($finalstring.Substring($startpos).Replace("Certificate Template Information","").Trim()) -split '\r?\n').Trim() | Select-String -Pattern "Template=" | Out-String).Replace("Template=","")
        $CertificateTemplate = $CertificateTemplateInfo.Split("(")[0].Trim();
        $CertificateTemplateOID = $CertificateTemplateInfo.Split("(")[1].Replace(")","").Trim();
        $MajorTemplateVersion = (($finalstring -split '\r?\n').Trim() | Select-String -Pattern "Major Version Number=" | Out-String).Replace("Major Version Number=","").Trim();
        $MinorTemplateVersion = (($finalstring -split '\r?\n').Trim() | Select-String -Pattern "Minor Version Number=" | Out-String).Replace("Minor Version Number=","").Trim();

        ## Application Policies
        $ApplicationPolicyOID = "1.3.6.1.4.1.311.21.10";
        $startpos = $certDump.IndexOf("1.3.6.1.4.1.311.21.10:");
        $subString = $certDump.Substring($startpos);
        $endpos = $substring.IndexOf("0000");
        $finalString = $subString.Substring(0, $endpos);
        $startpos = $finalstring.IndexOf("Application Policies")

            ## Regex to get each App Policy
            $AppStringArray = @(($finalstring.Substring($startpos) -split '\r?\n').Trim() | Select-String -Pattern '[\d]');
            $AppStringArrayCount = $AppStringArray.Count

            ## Create the app policy array
            $AppPolicyArray = @();
            
            ## Extract value for each App Policy in array
            foreach ($app in $appStringArray) {
                if ($app -eq $AppStringArray[-1]) {
                    ## Remove all text from before the final app
                    $startpos = $finalstring.IndexOf($app)
                    $AppID = (($finalstring.Substring($startpos) -split '\r?\n').Trim() | Select-String -Pattern "Policy Identifier=" | Out-String).Replace("Policy Identifier=","").Trim();
                    $AppPolicyArray += $AppID;
                }
                else {
                    ## Get the next app in the policy array as ending position
                    $nextApp = [int]($App -split ']')[0].Replace("[","") + 1;
                    $nextAppendPos = "[" + "$NextApp" + "]Application Certificate Policy:"

                    ## Get this app policy blob
                    $startpos = $finalstring.IndexOf($app) ;
                    $newFinalString = $FinalString.Substring($startpos);
                    $endpos = $newfinalstring.IndexOf($nextAppendPos);
                    $FinalFinalString = $newfinalString.Substring(0, $endpos);
                    $appID = (($FinalFinalstring -split '\r?\n').Trim() | Select-String -Pattern "Policy Identifier=" | Out-String).Replace("Policy Identifier=","").Trim();
                    $AppPolicyArray += $AppID;
                };

            };


        ## Create PSObject for this cert
        $cert = [pscustomobject]@{
        "Version" = $certVersion
        "Serial Number"= $certSerial
        "SignatureAlgorithm"= [pscustomobject]@{
            "Algorithm ObjectId" = $signatureAlgorithm_AlgorithmObjectID
            "Algorithm Parameters" = $signatureAlgorithm_AlgorithmParamters
        }
        "Issuer"= [pscustomobject]@{
            "CN"= $issuerCN
            "OU"= $issuerOUs
            "O"= $issuerOrgs
            "L"= $issuerLocality
            "ST"=$issuerState
            "C"= $issuerCountry 
            "E"= $issuerEmails
            "Name Hash (sha1)"= $subjectNameHashSHA1
            "Name Hash (md5)"= $subjectNameHashmd5
        }
        "NotBefore"= $certNotBeforeGMT
        "NotAfter"= $certNotAfterGMT 
        "Subject"= [pscustomobject]@{
            "CN"= $subjectCN
            "OU"= $subjectOUs
            "O"= $subjectOrgs
            "L"= $subjectLocality
            "ST"=$subjectState
            "C"= $subjectCountry 
            "E"= $subjectEmails
            "Name Hash (sha1)"= $subjectNameHashSHA1
            "Name Hash (md5)"= $subjectNameHashmd5
            "Public Key Algorithm"= [pscustomobject]@{
                "Algorithm ObjectId"= $publicKeyAlgorithm_AlgorithmObjectID
                "Algorithm Paramters"= $publicKeyAlgorithm_AlgorithmParamters
            }
            "Public Key Length"= $certPublicKeyLength
            "Certificate Extensions"= [pscustomobject]@{
                "Certificate Extensions Count" = $certExtensionsCount
                "Subject Key Identifier" = [pscustomobject]@{
                    "OID" = $subjectKeyIdentifierOID
                    "Value" = $subjectKeyIdentifier
                }
                "Key Usage" = [pscustomobject]@{
                    "OID" = $KeyUsageOID
                    "Value" = $KeyUsage
                }
                "Enhanced Key Usage" = [pscustomobject]@{
                    "OID" = $EnhancedKeyUsageOID
                    "Value" = $EnhancedKeyUsage
                }
                "Subject Alternative Name" = [pscustomobject]@{
                    "OID" = $SubjectAlternativeNameOID
                    "Value" = $SubjectAlternativeNames
                }
                "Authority Key Identifier" = [pscustomobject]@{
                    "OID" = $AuthorityKeyIdentifierOID
                    "Value" = $AuthorityKeyIdentifier
                }
                "CRL Distribution Point" = [pscustomobject]@{
                    "OID" = $CRLDistributionPointOID
                    "Value" = $CRLDistributionPoint
                }
                "Certificate Template" = [pscustomobject]@{
                    "OID" = $CertificateTemplateOID
                    "Value" = [pscustomobject]@{
                        "Template Name" = $CertificateTemplate
                        "Template OID"  = $CertificateTemplateOID
                        "Template Major Version" = $MajorTemplateVersion
                        "Template Minor Version" = $MinorTemplateVersion
                    }
                }
                "Application Policies" = [pscustomobject]@{
                    "OID" = $ApplicationPolicyOID
                    "Value" = $AppPolicyArray
                }
            }
        }
        };
    
    Write-Output $Cert;
    
    };

