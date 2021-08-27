using DocumentSealing.Models;
using iText.Forms;
using iText.Forms.Fields;
using iText.Kernel.Pdf;
using iText.Signatures;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Web.Http;

namespace DocumentSealing.Controllers
{
    public class VerifyController : ApiController
    {
        public VerificationResult Post([FromBody] SealedContent value)
        {
            VerificationResult result = Verify(value);
            return result;
        }

        private VerificationResult Verify(SealedContent sealedContent)
        {
            byte[] sealedBytes = Convert.FromBase64String(sealedContent.Content);

            string dataBag = null;
            bool acceptedFormat = false;
            bool signatureCoversWholeDocument = false;
            bool signatureIsValid = false;
            bool timestampIsValid = false;
            string error = null;

            using (MemoryStream inputStream = new MemoryStream(sealedBytes))
            {
                PdfDocument pdfDoc = new PdfDocument(new PdfReader(inputStream));

                PdfAcroForm form = PdfAcroForm.GetAcroForm(pdfDoc, false);
                IDictionary<string, PdfFormField> fields = form.GetFormFields();
                if (fields.ContainsKey("databag"))
                {
                    PdfFormField dataBagField = fields["databag"];
                    dataBag = dataBagField.GetValueAsString();
                    acceptedFormat = true;
                }

                SignatureUtil signUtil = new SignatureUtil(pdfDoc);
                IList<string> names = signUtil.GetSignatureNames();

                try
                {
                    if (names.Count != 1)
                    {
                        throw new Exception($"Expected one sealing signature, found {names.Count} signatures.");
                    }
                    string name = names[0];
                    PdfPKCS7 pkcs7 = signUtil.ReadSignatureData(name);
                    signatureCoversWholeDocument = signUtil.SignatureCoversWholeDocument(name);
                    signatureIsValid = pkcs7.VerifySignatureIntegrityAndAuthenticity();
                    timestampIsValid = pkcs7.VerifyTimestampImprint();
                }
                catch (Exception ex)
                {
                    error = ex.ToString();
                }
            }

            return new VerificationResult()
            {
                AcceptedFormat = acceptedFormat,
                ValidSignature = signatureIsValid && signatureCoversWholeDocument,
                ValidTimestamp = timestampIsValid,
                DataBag = dataBag,
                Error = error
            };
        }
    }
}
