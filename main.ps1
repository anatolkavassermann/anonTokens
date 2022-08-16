Add-Type -Path .\BouncyCastle.dll
$mainConfig = gc .\config.json | ConvertFrom-Json
function Send-HttpResponse {
    param (
        [Parameter(Mandatory=$true)] [System.Net.HttpListenerContext] $context,
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)] [System.String] $result
    )
    $buffer = [System.Text.Encoding]::UTF8.GetBytes($result);
    $context.Response.ContentLength64 = $buffer.Length;
    $context.Response.OutputStream.Write($buffer,0,$buffer.Length);
    $context.Response.Close();
}
function Sign-TimeStamp {
    param (
        $query
    )
    $builder = [Org.BouncyCastle.Pkcs.Pkcs12StoreBuilder]::new()
    [void]$builder.SetUseDerEncoding($true)
    $store = $builder.Build()
    $store.Load([System.IO.MemoryStream]::new([System.IO.File]::ReadAllBytes((gi ".\pfx.pfx"))), $mainConfig.pfxPass.ToCharArray().ToCharArray())
    [Org.BouncyCastle.Pkcs.AsymmetricKeyEntry] $prkBag = $store.GetKey("prk")
    [Org.BouncyCastle.Pkcs.X509CertificateEntry] $certbag = $store.GetCertificate("cert")
    [System.Collections.Generic.List[Org.BouncyCastle.X509.X509Certificate]]$certList = [System.Collections.Generic.List[Org.BouncyCastle.X509.X509Certificate]]::new()
    $certList.Add($certbag.Certificate)
    $storeParams = [Org.BouncyCastle.X509.Store.X509CollectionStoreParameters]::new($certList)
    $certStore = [Org.BouncyCastle.X509.Store.X509StoreFactory]::Create("Certificate/Collection", $storeParams)
    $pbk = [Org.BouncyCastle.Crypto.Parameters.ECPublicKeyParameters]$certbag.Certificate.GetPublicKey()
    $pbkParams = [Org.BouncyCastle.Crypto.Parameters.ECGost3410Parameters]$pbk.Parameters
    $essV2Cert = [Org.BouncyCastle.Asn1.Ess.EssCertIDv2]::new(
        [Org.BouncyCastle.Asn1.X509.AlgorithmIdentifier]::new($pbkParams.DigestParamSet.Id),
        [Org.BouncyCastle.Security.DigestUtilities]::CalculateDigest($pbkParams.DigestParamSet.Id, $certbag.Certificate.GetEncoded()),
        [Org.BouncyCastle.Asn1.X509.IssuerSerial]::new(
            [Org.BouncyCastle.Asn1.X509.GeneralNames]::new(
                [Org.BouncyCastle.Asn1.X509.GeneralName]::new(
                    $certbag.Certificate.IssuerDN
                )
            ),
            $certbag.Certificate.SerialNumber
        )
    )
    $signingCertV2 = [Org.BouncyCastle.Asn1.Ess.SigningCertificateV2]::new(
        [Org.BouncyCastle.Asn1.Ess.EssCertIDv2[]] @(
            $essV2Cert
        )
    )
    $fileHash = [Org.BouncyCastle.Security.DigestUtilities]::CalculateDigest($pbkParams.DigestParamSet.Id, [Org.BouncyCastle.Math.BigInteger]::new($query.GetValues("timestamp")).ToByteArray())
    $EssCertIDv2attb =  [Org.BouncyCastle.Asn1.Cms.Attribute]::new(
        [Org.BouncyCastle.Asn1.Pkcs.PkcsObjectIdentifiers]::IdAASigningCertificateV2, 
        [Org.BouncyCastle.Asn1.DerSet]::new($signingCertV2)
    )
    $SigningTimeattb = [Org.BouncyCastle.Asn1.Cms.Attribute]::new(
        [Org.BouncyCastle.Asn1.Pkcs.PkcsObjectIdentifiers]::Pkcs9AtSigningTime, 
        [Org.BouncyCastle.Asn1.DerSet]::new([Org.BouncyCastle.Asn1.DerUtcTime]::new([System.DateTime]::NOW))
    )
    $ContentTypeattb = [Org.BouncyCastle.Asn1.Cms.Attribute]::new(
        [Org.BouncyCastle.Asn1.Cms.CmsAttributes]::ContentType,
        [Org.BouncyCastle.Asn1.DerSet]::new([Org.BouncyCastle.Asn1.DerObjectIdentifier]::new("1.3.6.1.5.5.7.12.2"))
    )
    $MessageDigestattb = [Org.BouncyCastle.Asn1.Cms.Attribute]::new(
        [Org.BouncyCastle.Asn1.Cms.CmsAttributes]::MessageDigest,
        [Org.BouncyCastle.Asn1.DerSet]::new([Org.BouncyCastle.Asn1.DerOctetString]::new($fileHash))
    )
    $SignedAttbs = @{}
    $SignedAttbs.Add([Org.BouncyCastle.Asn1.DerObjectIdentifier]$EssCertIDv2attb.AttrType, $EssCertIDv2attb)
    $SignedAttbs.Add([Org.BouncyCastle.Asn1.DerObjectIdentifier]$SigningTimeattb.AttrType, $SigningTimeattb)
    $SignedAttbs.Add([Org.BouncyCastle.Asn1.DerObjectIdentifier]$ContentTypeattb.AttrType, $ContentTypeattb)
    $SignedAttbs.Add([Org.BouncyCastle.Asn1.DerObjectIdentifier]$MessageDigestattb.AttrType, $MessageDigestattb)
    $signedAttributesTable = [Org.BouncyCastle.Asn1.Cms.AttributeTable]::new($SignedAttbs)
    $signedAttributeGenerator = [Org.BouncyCastle.Cms.DefaultSignedAttributeTableGenerator]::new($signedAttributesTable)
    $gen = [Org.BouncyCastle.Cms.CmsSignedDataGenerator]::new()
    $gen.UseDerForCerts = $true
    $gen.AddCertificates($certStore)
    $gen.AddSigner([Org.BouncyCastle.Crypto.AsymmetricKeyParameter]$prkBag.Key, $certbag.Certificate, $pbkParams.DigestParamSet.Id, $signedAttributeGenerator, $null)
    $message = [Org.BouncyCastle.Cms.CmsProcessableByteArray]::new([Org.BouncyCastle.Math.BigInteger]::new($query.GetValues("timestamp")).ToByteArray())
    $attachedCms = $gen.Generate($message, $true)
    [System.Convert]::ToBase64String($attachedCms.GetEncoded("DER")) | sv -Name "SigB64"
    return $SigB64
}
$mustContainParams = [System.Collections.Specialized.NameValueCollection]::new();
$tokenGiverHttpListener = [System.Net.HttpListener]::new()
$tokenGiverHttpListener | % { $_.Prefixes.Add("http://127.0.0.1:11001/"); $_.Start() }
while ($tokenGiverHttpListener.IsListening) {
    $context = $tokenGiverHttpListener.GetContext()
    if ($context.Request.Url.LocalPath -eq "/favicon.ico") {
        continue;
    }
    else {
        Write-Host -BackgroundColor Green -ForegroundColor Black -Object "Context captured!"
        $query = $context.Request.QueryString
        $queryToken = ($query.GetValues("token") | select -Last 1)
        if ($null -eq $queryToken) {
            "No token presented!" | Send-HttpResponse -context $context
            continue
        }
        else {
            $mustContainParams.Clear()
            $mustContainParams.Add("token", $mainConfig.applicationToken)
            if  (($query.GetValues("token") | select -Last 1) -eq ($mustContainParams.GetValues("token")| select -Last 1)) {
                switch ($context.Request.Url.LocalPath) {
                    "/" {
                        $mustContainParams.Add("email", "")
                        $mustContainParams.Add("timestamp", "")
                        if ([System.Linq.Enumerable]::SequenceEqual($mustContainParams.AllKeys, [System.Linq.Enumerable]::Intersect($mustContainParams.AllKeys, $query.AllKeys))) {
                            Sign-TimeStamp -query $query | Send-HttpResponse -context $context
                            $signature = Sign-TimeStamp -query $query

                            Send-MailMessage `
                                -SmtpServer $mainConfig.SmtpServer `
                                -From $mainConfig.email `
                                -To ($query.GetValues("email") | select -Last 1) `
                                -Subject "Token!" `
                                -Body $signature `
                                -Credential ([System.Management.Automation.PSCredential]::new(
                                    $mainConfig.email,
                                    (ConvertTo-SecureString $mainConfig.password -AsPlainText -Force)
                                ))
                            continue
                        }
                        else {
                            "Not all params presented!" | Send-HttpResponse -context $context
                            continue
                        }
                        break;
                    }
                }
            }
            else {
                "Wrong token presented!" | Send-HttpResponse -context $context
                continue
            }
        }
    }
}