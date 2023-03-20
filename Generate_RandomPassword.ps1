Function Generate_RandomPassword {
    <#

    .SYNOPSIS
    Generates a random password of defined length

    .DESCRIPTION
    Generate a random password using openssl rand function. Generates random output utilizing the CSPRNG secure pseudo-random number generator. 

    .EXAMPLE
    Generate_RandomPassword -PasswordLength 12
    
    .EXAMPLE
    Generate_RandomPassword -PasswordLength 32

    .NOTES
    Author: Charles Hamby
    Date: 6/22/2022
    Requires OpenSSL
    

    .PARAMETER PasswordLength <Int>
    Accept pipeline input?   true
    Aliases                  None

    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        [Int]$PasswordLength = "15"
    )

    

    Try {

        # Send the API call and store it in a variable
        [string]$output = Openssl rand -base64 256;
        $Output.Replace(" ","")
        $Output.Substring(0,$PasswordLength);
    
    }
    catch {

        $Message = $Global:Error[0]
        throw $Message

    };

}
