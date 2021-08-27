using iText.Kernel.Geom;
using iText.Kernel.Pdf;
using iText.Signatures;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.Tsp;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Configuration;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace DocumentSealing.Providers
{
    public class GlobalSign
    {
        private static readonly string _baseUrl = ConfigurationManager.AppSettings["GlobalSign.BaseUrl"];
        private static readonly string _apiKey = ConfigurationManager.AppSettings["GlobalSign.ApiKey"];
        private static readonly string _apiSecret = ConfigurationManager.AppSettings["GlobalSign.ApiSecret"];
        private static readonly string _pfxFileName = ConfigurationManager.AppSettings["GlobalSign.PFXFile"];
        private static readonly string _pfxPassword = ConfigurationManager.AppSettings["GlobalSign.PFXPassword"];
        private static readonly string _signatureFieldName = ConfigurationManager.AppSettings["GlobalSign.SignatureFieldName"];

        private static HttpClient _client;
        private static X509Certificate2Collection collection;

        static GlobalSign()
        {
            HttpClientHandler handler = new HttpClientHandler();
            handler.ClientCertificateOptions = ClientCertificateOption.Manual;
            handler.SslProtocols = SslProtocols.Tls12;
            handler.ClientCertificates.Add(new System.Security.Cryptography.X509Certificates.X509Certificate2(_pfxFileName, _pfxPassword));
            _client = new HttpClient(handler);
        }

        public byte[] Seal(byte[] inputBytes)
        {
            byte[] outputBytes;
            byte[] tempBytes;

            collection = new X509Certificate2Collection();
            collection.Import(_pfxFileName, _pfxPassword, X509KeyStorageFlags.DefaultKeySet);
            ServicePointManager.Expect100Continue = true;
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;


            //get JSON access token
            JObject access = Login(_baseUrl, _apiKey, _apiSecret);

            // info for organization certificate has been pre-populated so we send an empty
            // request
            JObject apiID = new JObject();

            //get JSON with id/certificate/ocsp response
            JObject identity = Identity(_baseUrl, access, apiID);
            String cert = (String)identity.GetValue("signing_cert");
            String id = (String)identity.GetValue("id");
            String oc1 = (String)identity.GetValue("ocsp_response");

            //Create Certificate chain
            JObject path = CertificatePath(_baseUrl, access);
            String ca = (String)path.GetValue("path");
            X509Certificate[] chain = CreateChain(cert, ca);

            //If validation policy is needed
            JObject policy = ValidationPolicy(_baseUrl, access);

            //If trust chain is needed
            JObject trustChain = TrustChain(_baseUrl, access);
            JArray trustChainJSONArray = (JArray)trustChain.GetValue("trustchain");
            JArray trustChainOCSP = (JArray)trustChain.GetValue("ocsp_revocation_info");


            PdfReader reader;
            using (MemoryStream inputStream = new MemoryStream(inputBytes))
            {
                reader = new PdfReader(inputStream);
            }

            using (MemoryStream outputStream = new MemoryStream())
            {
                PdfSigner stamper = new PdfSigner(reader, outputStream, new StampingProperties());

                PdfSignatureAppearance appearance = stamper.GetSignatureAppearance();
                appearance.SetPageRect(new Rectangle(50, 570, 0, 0)); // set width and height to zero for invisible
                appearance.SetPageNumber(1);
                appearance.SetLayer2FontSize(14f);

                stamper.SetFieldName(_signatureFieldName);

                appearance.SetCertificate(chain[0]);

                stamper.SetCertificationLevel(PdfSigner.CERTIFIED_NO_CHANGES_ALLOWED);

                IExternalSignatureContainer external = new ExternalBlankSignatureContainer(PdfName.Adobe_PPKLite, PdfName.Adbe_pkcs7_detached);

                stamper.SignExternalContainer(external, 8192 * 2);

                tempBytes = outputStream.ToArray();
            }

                // Embed either OCSPs or CRLs, there is no need to include both.
                // Using all OCSPs
                // Add all ocsp string together in a list
                List<string> ocspStringCollection = new List<string>();
                ocspStringCollection.Add(oc1);
                // Put all the OCSP base64 string in a list
                for (int i = 0; i < trustChainOCSP.Count; i++)
                {
                    string ocspString = trustChainOCSP.Value<string>(i);
                    ocspStringCollection.Add(ocspString);
                }
                // Convert all ocsp string to ASN1 encoded in 4 steps
                ICollection<byte[]> ocspASN1Collection = new Collection<byte[]>();
                for (int i = 0; i < ocspStringCollection.Count; i++)
                {
                    String ocspString = ocspStringCollection[i];
                    // Decode base64 oscsp string
                    byte[] ocspByte = Convert.FromBase64String(ocspString);
                    // create OCSPResp from base64 byte
                    OcspResp ocspResp = new OcspResp(ocspByte);
                    // create BasicOCSPResp from OCSPResp
                    BasicOcspResp basicResp = (BasicOcspResp)ocspResp.GetResponseObject();
                    // Get ASN1 Encoded
                    byte[] ocspASN1 = basicResp.GetEncoded();
                    ocspASN1Collection.Add(ocspASN1);
                }

                IExternalSignatureContainer gsContainer = new MyExternalSignatureContainer(id, access, chain, ocspASN1Collection, null);
                
                using (MemoryStream ltvStream = new MemoryStream())
                {
                    PdfSigner signer = new PdfSigner(GetPdfReader(tempBytes), ltvStream, new StampingProperties());
                    PdfSigner.SignDeferred(signer.GetDocument(), _signatureFieldName, ltvStream, gsContainer);
                    ltvStream.Flush();
                    ltvStream.Position = 0;
                    outputBytes = ltvStream.ToArray();
                }


            

            // This does not work with Certifying with LTV with No changes allowed options.
            //AddLTV(DEST, LTV, new OcspClientBouncyCastle(null), new CrlClientOnline(), LtvVerification.Level.OCSP_CRL, LtvVerification.Level.OCSP_CRL);

            return outputBytes;
        }

        private static PdfReader GetPdfReader(byte[] bytes)
        {
            PdfReader reader;
            using (MemoryStream ms = new MemoryStream(bytes))
            {
                reader = new PdfReader(ms);
            }
            return reader;
        }

        public static JObject Login(String aURL, String aKey, String aSecret)
        {
            Uri loginURL = new Uri(aURL + "/login");

            JObject apiLogin = new JObject();
            apiLogin.Add("api_key", aKey);
            apiLogin.Add("api_secret", aSecret);

            var httpWebRequest = (HttpWebRequest)WebRequest.Create(loginURL);
            httpWebRequest.Method = "POST";
            httpWebRequest.ContentType = "application/json; charset=UTF-8";
            httpWebRequest.ContentLength = apiLogin.ToString().Length;
            httpWebRequest.ClientCertificates = collection;

            //Send Request
            using (var streamWriter = new StreamWriter(httpWebRequest.GetRequestStream()))
            {
                streamWriter.Write(apiLogin.ToString());
            }

            //Get Response
            var httpResponse = (HttpWebResponse)httpWebRequest.GetResponse();
            string result;
            using (var streamReader = new StreamReader(httpResponse.GetResponseStream()))
            {
                result = streamReader.ReadToEnd();
            }

            JObject accessCode = JObject.Parse(result);

            return accessCode;
        }


        public static JObject Identity(String aURL, JObject aObj, JObject apiID)
        {
            Uri identityURL = new Uri(aURL + "/identity");
            String token = (String)aObj.GetValue("access_token");

            var httpWebRequest = (HttpWebRequest)WebRequest.Create(identityURL);
            httpWebRequest.Method = "POST";
            httpWebRequest.Headers.Add("Authorization", "Bearer " + token);
            httpWebRequest.ContentType = "application/json; charset=UTF-8";
            httpWebRequest.ContentLength = apiID.ToString().Length;
            httpWebRequest.ClientCertificates = collection;

            //Send Request
            using (var streamWriter = new StreamWriter(httpWebRequest.GetRequestStream()))
            {
                streamWriter.Write(apiID.ToString());
            }

            //Get Response
            var httpResponse = (HttpWebResponse)httpWebRequest.GetResponse();
            string result;
            using (var streamReader = new StreamReader(httpResponse.GetResponseStream()))
            {
                result = streamReader.ReadToEnd();
            }

            JObject identity = JObject.Parse(result);

            return identity;
        }

        public static JObject CertificatePath(String aURL, JObject aObj)
        {
            Uri certificatePathURL = new Uri(aURL + "/certificate_path");

            String token = (String)aObj.GetValue("access_token");

            var httpWebRequest = (HttpWebRequest)WebRequest.Create(certificatePathURL);
            httpWebRequest.Method = "GET";
            httpWebRequest.Headers.Add("Authorization", "Bearer " + token);
            httpWebRequest.ClientCertificates = collection;

            //Get Response
            var httpResponse = (HttpWebResponse)httpWebRequest.GetResponse();
            string result;
            using (var streamReader = new StreamReader(httpResponse.GetResponseStream()))
            {
                result = streamReader.ReadToEnd();
            }

            JObject path = JObject.Parse(result);

            return path;
        }

        public static X509Certificate[] CreateChain(String cert, String ca)
        {
            X509Certificate[] chainy = new X509Certificate[2];

            X509CertificateParser parser = new X509CertificateParser();

            chainy[0] = new X509Certificate(parser.ReadCertificate(Encoding.UTF8.GetBytes(cert)).CertificateStructure);
            chainy[1] = new X509Certificate(parser.ReadCertificate(Encoding.UTF8.GetBytes(ca)).CertificateStructure);

            return chainy;
        }

        public static JObject Timestamp(String aURL, String digest, JObject aObj)
        {
            Uri timestampURL = new Uri(aURL + "/timestamp/" + digest);


            String token = (String)aObj.GetValue("access_token");

            var httpWebRequest = (HttpWebRequest)WebRequest.Create(timestampURL);
            httpWebRequest.Method = "GET";
            httpWebRequest.Headers.Add("Authorization", "Bearer " + token);
            httpWebRequest.ClientCertificates = collection;

            //Get Response
            var httpResponse = (HttpWebResponse)httpWebRequest.GetResponse();
            string result;
            using (var streamReader = new StreamReader(httpResponse.GetResponseStream()))
            {
                result = streamReader.ReadToEnd();
            }

            JObject time = JObject.Parse(result);

            return time;
        }

        public static JObject Sign(String aURL, String id, String digest, JObject aObj)
        {
            Uri signURL = new Uri(aURL + "/identity/" + id + "/sign/" + digest);

            String token = (String)aObj.GetValue("access_token");

            var httpWebRequest = (HttpWebRequest)WebRequest.Create(signURL);
            httpWebRequest.Method = "GET";
            httpWebRequest.Headers.Add("Authorization", "Bearer " + token);
            httpWebRequest.ClientCertificates = collection;

            //Get Response
            var httpResponse = (HttpWebResponse)httpWebRequest.GetResponse();
            string result;
            using (var streamReader = new StreamReader(httpResponse.GetResponseStream()))
            {
                result = streamReader.ReadToEnd();
            }

            JObject signature = JObject.Parse(result);

            return signature;
        }

        public static JObject ValidationPolicy(String aURL, JObject aObj)
        {
            Uri validationPolicyURL = new Uri(aURL + "/validationpolicy");


            String token = (String)aObj.GetValue("access_token");

            var httpWebRequest = (HttpWebRequest)WebRequest.Create(validationPolicyURL);
            httpWebRequest.Method = "GET";
            httpWebRequest.Headers.Add("Authorization", "Bearer " + token);
            httpWebRequest.ClientCertificates = collection;

            //Get Response
            var httpResponse = (HttpWebResponse)httpWebRequest.GetResponse();
            string result;
            using (var streamReader = new StreamReader(httpResponse.GetResponseStream()))
            {
                result = streamReader.ReadToEnd();
            }

            JObject policy = JObject.Parse(result);

            return policy;
        }

        public static JObject TrustChain(String aURL, JObject aObj)
        {
            Uri trustChainURL = new Uri(aURL + "/trustchain");

            String token = (String)aObj.GetValue("access_token");

            var httpWebRequest = (HttpWebRequest)WebRequest.Create(trustChainURL);
            httpWebRequest.Method = "GET";
            httpWebRequest.Headers.Add("Authorization", "Bearer " + token);
            httpWebRequest.ClientCertificates = collection;

            //Get Response
            var httpResponse = (HttpWebResponse)httpWebRequest.GetResponse();
            string result;
            using (var streamReader = new StreamReader(httpResponse.GetResponseStream()))
            {
                result = streamReader.ReadToEnd();
            }

            JObject trustChain = JObject.Parse(result);

            return trustChain;
        }


        class DSSTSAClient : ITSAClient
        {
            public static int DEFAULTTOKENSIZE = 4096;
            public static String DEFAULTHASHALGORITHM = "SHA-256";
            private JObject accessToken;

            public DSSTSAClient(JObject accessToken)
            {
                this.accessToken = accessToken;
            }

            public IDigest GetMessageDigest()
            {
                return new Sha256Digest();
            }

            public byte[] GetTimeStampToken(byte[] imprint)
            {
                TimeStampRequestGenerator tsqGenerator = new TimeStampRequestGenerator();
                tsqGenerator.SetCertReq(true);

                BigInteger nonce = BigInteger.ValueOf((long)(new TimeSpan(DateTime.Now.Ticks)).TotalMilliseconds);

                TimeStampRequest request = tsqGenerator.Generate(new DerObjectIdentifier(
                        DigestAlgorithms.GetAllowedDigest(DEFAULTHASHALGORITHM)),
                    imprint, nonce);

                JObject time = Timestamp(_baseUrl, Hex.ToHexString(request.GetMessageImprintDigest()),
                    accessToken);
                String tst = (String)time.GetValue("token");
                byte[] token = Base64.Decode(tst);

                CmsSignedData cms = new CmsSignedData(token);

                TimeStampToken tstToken = new TimeStampToken(cms);
                return tstToken.GetEncoded();
            }

            public int GetTokenSizeEstimate()
            {
                return DEFAULTTOKENSIZE;
            }
        }


        class MyExternalSignatureContainer : IExternalSignatureContainer
        {
            private String id;
            private X509Certificate[] chain;
            private JObject access;
            private OcspResp ocspResp;
            private ICollection<byte[]> ocspCollection;
            private ICollection<byte[]> crlCollection;

            public MyExternalSignatureContainer(String id, JObject access, X509Certificate[] chain, ICollection<byte[]> ocspCollection, ICollection<byte[]> crlCollection)
            {
                this.id = id;
                this.access = access;
                this.chain = chain;
                this.ocspCollection = ocspCollection;
                this.crlCollection = crlCollection;
            }

            public byte[] Sign(Stream data)
            {
                String hashAlgorithm = "SHA256";
                PdfPKCS7 sgn = new PdfPKCS7(null, chain, hashAlgorithm, false);

                byte[] hash = DigestAlgorithms.Digest(data, DigestAlgorithms.GetMessageDigest(hashAlgorithm));

                byte[] sh = sgn.GetAuthenticatedAttributeBytes(hash, PdfSigner.CryptoStandard.CADES, ocspCollection,
                    crlCollection);

                //create sha256 message digest
                using (SHA256 sha256 = SHA256.Create())
                {
                    sh = sha256.ComputeHash(sh);
                }

                //create hex encoded sha256 message digest
                String hexencodedDigest = new BigInteger(1, sh).ToString(16).ToUpper();

                JObject signed = GlobalSign.Sign(_baseUrl, id, hexencodedDigest, access);
                String sig = (String)signed.GetValue("signature");

                //decode hex signature
                byte[] dsg = Hex.Decode(sig);

                //include signature on PDF
                sgn.SetExternalDigest(dsg, null, "RSA");

                //create TimeStamp Client
                ITSAClient tsc = new DSSTSAClient(access);

                return sgn.GetEncodedPKCS7(hash, PdfSigner.CryptoStandard.CADES, tsc, ocspCollection, crlCollection);
            }

            public void ModifySigningDictionary(PdfDictionary signDic)
            {
            }
        }
    }
}