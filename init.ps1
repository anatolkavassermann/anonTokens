Add-Type -Path .\BouncyCastle.dll
#
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
$store.Save($m, "12345".ToCharArray(), $secureRandom);
$data = $m.ToArray()
$pkcs12Bytes = [Org.BouncyCastle.Pkcs.Pkcs12Utilities]::ConvertToDefiniteLength($data)
[System.IO.File]::WriteAllBytes("pfx.pfx", $pkcs12Bytes)


# $target = @"
# using System.Text;
# using System.Collections;
# using Org.BouncyCastle.Pkcs;
# using Org.BouncyCastle.OpenSsl;
# using Org.BouncyCastle.X509;
# using Org.BouncyCastle.Crypto;
# using Org.BouncyCastle.Security;
# using Org.BouncyCastle.Crypto.Parameters;
# using Org.BouncyCastle.Asn1.Ess;
# using Org.BouncyCastle.Asn1;
# using Org.BouncyCastle.Asn1.X509;
# using Org.BouncyCastle.Asn1.Pkcs;
# using Org.BouncyCastle.Asn1.Cms;
# using Org.BouncyCastle.Cms;
# using Org.BouncyCastle.X509.Store;
# using Org.BouncyCastle.Asn1.CryptoPro;
# using Org.BouncyCastle.Crypto.Generators;
# using Org.BouncyCastle.Crypto.Signers;
# using Org.BouncyCastle.Utilities.Encoders;
# using Org.BouncyCastle.Crypto.Operators;
# using Org.BouncyCastle.Asn1.Rosstandart;

# namespace MyCSP {
#     public class Initialiser {
#         //keydata
#         var PrKeyFileName = "prk.pem";
#         var PbKeyFileName = "pbk.pem";
#         //Rawsig FileName
#         var RawSigFileName = "toBeSignedRaw.sig";
        
#         //For CA
#         var CertRequestFileName = "req.req";
#         var SelfSignedCertFileName = "cert.crt";
#         var IssuedCertFileName = "issued_cert.crt";
#         var cpro = "certnew.cer";
#         var CrlFileName = "crl.crl";
        
#         //For PFX
#         var PFXFileName = "pfx.pfx";
#         var PFXPass = "12345qwerty";
        
#         //For CAdES, XMLDSIG and PAdES
#         var CAdESBES_SigFileName = "toBeSigned_CAdESBES.sig";
#         var XMLDSIG_SigFileName = "XMLtoBeSigned_XMLDSIG.signed.xml";
#         var PAdES_SigFileName = "PDFtoBeSigned_PAdES.signed.pdf";
        
#         //For export certs from cpro key container
#         var Header_Key_FileName = "header.key";

#         public static void Main () {
#             var secureRandom = new SecureRandom();
#             var curve = ECGost3410NamedCurves.GetByNameX9("Tc26-Gost-3410-12-256-paramSetA");
#             var domainParams = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H, curve.GetSeed());
#             var ECGost3410Parameters = new ECGost3410Parameters(
#                 new ECNamedDomainParameters(new DerObjectIdentifier("1.2.643.7.1.2.1.1.1"), domainParams),
#                 new DerObjectIdentifier("1.2.643.7.1.2.1.1.1"),
#                 new DerObjectIdentifier("1.2.643.7.1.1.2.2"),
#                 null
#             );
#             var ECKeyGenerationParameters = new ECKeyGenerationParameters(ECGost3410Parameters, secureRandom);
#             var keyGenerator = new ECKeyPairGenerator();
#             keyGenerator.Init(ECKeyGenerationParameters);
#             var keyPair = keyGenerator.GenerateKeyPair();
#             WritePemObject(keyPair.Private, _PrKeyFileName);
# 			WritePemObject(keyPair.Public, _PbKeyFileName);
#             ECPrivateKeyParameters prk = (ECPrivateKeyParameters)ReadPemObject(_PrKeyFileName);
# 	        ECPublicKeyParameters pbk = (ECPublicKeyParameters)ReadPemObject(_PbKeyFileName);
#             Org.BouncyCastle.Math.BigInteger serial = new Org.BouncyCastle.Math.BigInteger(160, secureRandom);
#             var certGen = new X509V3CertificateGenerator();
#             certGen.SetSerialNumber(serial);
#             certGen.SetIssuerDN(new X509Name("CN="));
#             certGen.SetNotBefore(DateTime.UtcNow);
#             certGen.SetNotAfter(DateTime.UtcNow.AddYears(1));
#             certGen.SetPublicKey(pbk);
#             certGen.SetSubjectDN(new X509Name("CN="));

#             var subjectPbkInfo = new SubjectPublicKeyInfo(new AlgorithmIdentifier("1.2.643.7.1.2.1.1.1"), pbk.Q.GetEncoded());
#             var subjectKeyID = new SubjectKeyIdentifier(subjectPbkInfo);

#             certGen.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(240));
#             certGen.AddExtension(new DerObjectIdentifier("2.5.29.37"), false, new DerSequence(new DerObjectIdentifier("1.3.6.1.5.5.7.3.2")));
#             certGen.AddExtension(new DerObjectIdentifier("2.5.29.14"), false, new DerOctetString(subjectKeyID.GetKeyIdentifier()));

#             var pbkParams = (ECGost3410Parameters)pbk.Parameters;
#             ISignatureFactory signatureFactory = new Asn1SignatureFactory(RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_256.Id, (AsymmetricKeyParameter)prk);
#             var x509 = certGen.Generate(signatureFactory);
#             WritePemObject(x509, _SelfSignedCertFileName);
#             ECPrivateKeyParameters prk = (ECPrivateKeyParameters)ReadPemObject(_PrKeyFileName);
#             X509Certificate x509 = (X509Certificate)ReadPemObject(_SelfSignedCertFileName);
#             var alias = x509.SubjectDN.GetValueList(new DerObjectIdentifier("2.5.4.3"));
#             var pkcs12Builder = new Pkcs12StoreBuilder();
#             pkcs12Builder.SetUseDerEncoding(true);
#             var store = pkcs12Builder.Build();
#             store.SetKeyEntry("prk", new AsymmetricKeyEntry((AsymmetricKeyParameter)prk), new X509CertificateEntry[] { new X509CertificateEntry(x509) });
#             store.SetCertificateEntry("cert", new X509CertificateEntry(x509));
#             var m = new MemoryStream();
#             store.Save(m, _PFXPass.ToCharArray(), secureRandom);
#             var data = m.ToArray();
#             var pkcs12Bytes = Pkcs12Utilities.ConvertToDefiniteLength(data);
#             File.WriteAllBytes(_PFXFileName, pkcs12Bytes);
#         }

#         private static void WritePemObject(Object _object, String _fileName) {
#             TextWriter TextWriter = File.CreateText($".\\{_fileName}");
#             var PemWriter = new PemWriter(TextWriter);
#             PemWriter.WriteObject(_object);
#             TextWriter.Flush();
#             TextWriter.Close();
#             TextWriter.Dispose();
#         }

#         private static System.Object ReadPemObject(String _fileName)
#         {
#             TextReader TextReader = File.OpenText($".\\{_fileName}");
#             var PemReader = new PemReader(TextReader);
#             var _object = PemReader.ReadObject();
#             TextReader.Close();
#             TextReader.Dispose();
#             return _object;
#         }
#     }
# }
# "@