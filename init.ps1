Add-Type -Path .\BouncyCastle.dll
#
$mainConfig = gc .\config.json | ConvertFrom-Json
$secureRandom = [Org.BouncyCastle.Security.SecureRandom]::new()
$curve = [Org.BouncyCastle.Asn1.CryptoPro.ECGost3410NamedCurves]::GetByNameX9("Tc26-Gost-3410-12-256-paramSetA")
$domainParams = [Org.BouncyCastle.Crypto.Parameters.ECDomainParameters]::new(
    $curve.Curve,
    $curve.G,
    $curve.N,
    $curve.H,
    $curve.GetSeed()
)
$ECGost3410Parameters = [Org.BouncyCastle.Crypto.Parameters.ECGost3410Parameters]::new(
    [Org.BouncyCastle.Crypto.Parameters.ECNamedDomainParameters]::new(
        [Org.BouncyCastle.Asn1.DerObjectIdentifier]::new("1.2.643.7.1.2.1.1.1"),
        $domainParams
    ),
    [Org.BouncyCastle.Asn1.DerObjectIdentifier]::new("1.2.643.7.1.2.1.1.1"),
    [Org.BouncyCastle.Asn1.DerObjectIdentifier]::new("1.2.643.7.1.1.2.2"),
    $null
)
$ECKeyGenerationParameters = [Org.BouncyCastle.Crypto.Parameters.ECKeyGenerationParameters]::new(
    $ECGost3410Parameters, 
    $secureRandom
)
$ECKeyPairGenerator = [Org.BouncyCastle.Crypto.Generators.ECKeyPairGenerator]::new()
$ECKeyPairGenerator.Init($ECKeyGenerationParameters);
$keyPair = $ECKeyPairGenerator.GenerateKeyPair()
$serial = [Org.BouncyCastle.Math.BigInteger]::new(160, $secureRandom)
$certGen = [Org.BouncyCastle.X509.X509V3CertificateGenerator]::new()
$certGen.SetSerialNumber($serial)
$certGen.SetIssuerDN(
    [Org.BouncyCastle.Asn1.X509.X509Name]::new("CN=TokenGiver")
)
$certGen.SetNotBefore([System.DateTime]::UtcNow)
$certGen.SetNotAfter([System.DateTime]::UtcNow.AddYears(1))
$certGen.SetPublicKey($keyPair.Public)
$certGen.SetSubjectDN(
    [Org.BouncyCastle.Asn1.X509.X509Name]::new("CN=TokenGiver")
)
$subjectPbkInfo = [Org.BouncyCastle.Asn1.X509.SubjectPublicKeyInfo]::new(
    [Org.BouncyCastle.Asn1.X509.AlgorithmIdentifier]::new("1.2.643.7.1.2.1.1.1"),
    $keyPair.Public.Q.GetEncoded()
)
$subjectKeyID = [Org.BouncyCastle.Asn1.X509.SubjectKeyIdentifier]::new($subjectPbkInfo)
$certGen.AddExtension(
    [Org.BouncyCastle.Asn1.X509.X509Extensions]::KeyUsage, 
    $true, 
    [Org.BouncyCastle.Asn1.X509.KeyUsage]::new(240)
)
$certGen.AddExtension(
    [Org.BouncyCastle.Asn1.DerObjectIdentifier]::new("2.5.29.37"), 
    $false, 
    [Org.BouncyCastle.Asn1.DerSequence]::new(
        [Org.BouncyCastle.Asn1.DerObjectIdentifier]::new("1.3.6.1.5.5.7.3.2")
    )
)
$certGen.AddExtension(
    [Org.BouncyCastle.Asn1.DerObjectIdentifier]::new("2.5.29.14"),
    $false, 
    [Org.BouncyCastle.Asn1.DerOctetString]::new(
        $subjectKeyID.GetKeyIdentifier()
    )
)
$signatureFactory = [Org.BouncyCastle.Crypto.Operators.Asn1SignatureFactory]::new(
    [Org.BouncyCastle.Asn1.Rosstandart.RosstandartObjectIdentifiers]::id_tc26_signwithdigest_gost_3410_12_256.Id,
    $keyPair.Private
)
$x509 = $certGen.Generate($signatureFactory)
$alias = $x509.SubjectDN.GetValueList([Org.BouncyCastle.Asn1.DerObjectIdentifier]::new("2.5.4.3"))
$pkcs12StoreBuilder = [Org.BouncyCastle.Pkcs.Pkcs12StoreBuilder]::new()
[void] $pkcs12StoreBuilder.SetUseDerEncoding($true)
$store = $pkcs12StoreBuilder.Build()
$store.SetKeyEntry(
    "prk",
    [Org.BouncyCastle.Pkcs.AsymmetricKeyEntry]::new($keyPair.Private),
    [Org.BouncyCastle.Pkcs.X509CertificateEntry]::new($x509) -as [Org.BouncyCastle.Pkcs.X509CertificateEntry[]]
)
$store.SetCertificateEntry(
    "cert",
    [Org.BouncyCastle.Pkcs.X509CertificateEntry]::new($x509)
)
$m = [System.IO.MemoryStream]::new()
$store.Save($m, $mainConfig.pfxPass.ToCharArray(), $secureRandom);
$data = $m.ToArray()
$pkcs12Bytes = [Org.BouncyCastle.Pkcs.Pkcs12Utilities]::ConvertToDefiniteLength($data)
[System.IO.File]::WriteAllBytes("pfx.pfx", $pkcs12Bytes)