using DocumentSealing.Models;
using DocumentSealing.Providers;
using iText.Forms;
using iText.Forms.Fields;
using iText.Html2pdf;
using iText.IO.Font;
using iText.Kernel.Geom;
using iText.Kernel.Pdf;
using iText.Layout;
using iText.Layout.Element;
using iText.Layout.Font;
using iText.StyledXmlParser.Jsoup.Nodes;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text.RegularExpressions;
using System.Web.Http;

namespace DocumentSealing.Controllers
{
    public class SealController : ApiController
    {
        public SealedContent Post([FromBody] SealInfo value)
        {
            byte[] sealedBytes = Seal(value);
            string sealedContent = Convert.ToBase64String(sealedBytes);
            return new SealedContent() { Encoding = "base64", Content = sealedContent };
        }

        private byte[] Seal(SealInfo sealInfo)
        {
            byte[] pdfBytes = Convert.FromBase64String(sealInfo.Document.FileContent);
            byte[] containerBytes;

            using (MemoryStream outputStream = new MemoryStream())
            {
                PdfDocument pdfDoc = GetPdfDocument(pdfBytes, outputStream);
                SetMetaData(pdfDoc, sealInfo.Creator);
                AddCustomPage(pdfDoc, sealInfo.CustomPageHtml);
                AddDataBag(pdfDoc, sealInfo.DataBag);
                pdfDoc.Close();
                containerBytes = outputStream.ToArray();
            }
            
            return GetSealedBytes(containerBytes);
        }

        private PdfDocument GetPdfDocument(byte[] pdfBytes, Stream outputStream)
        {
            PdfDocument pdfDoc = null;
            using (MemoryStream inputStream = new MemoryStream(pdfBytes))
            {
                pdfDoc = new PdfDocument(new PdfReader(inputStream), new PdfWriter(outputStream));
            }
            return pdfDoc;
        }

        private void SetMetaData(PdfDocument pdfDoc, string creator)
        {
            PdfDocumentInfo pdfDocInfo = pdfDoc.GetDocumentInfo();
            pdfDocInfo.SetCreator(creator);
        }

        private void AddCustomPage(PdfDocument pdfDoc, string customPageHtml)
        {
            PdfPage page = pdfDoc.AddNewPage();
            Canvas canvas = new Canvas(page, page.GetPageSize());
            FontProvider fontProvider = null;
            string fonts = ConfigurationManager.AppSettings["Fonts"];
            if (!string.IsNullOrEmpty(fonts))
            {
                IEnumerable<string> fontFiles = fonts.Split(new char[] { ',', ';' }, StringSplitOptions.RemoveEmptyEntries).Select(x => x.Trim());
                if (fontFiles.Count() > 0)
                {
                    fontProvider = new FontProvider();
                    foreach (string fontFile in fontFiles)
                    {
                        fontProvider.AddFont(fontFile);
                    }
                }
            }

            Div htmlContainer = null;
            if (fontProvider != null)
            {
                ConverterProperties properties = new ConverterProperties();
                properties.SetFontProvider(fontProvider);
                htmlContainer = (Div)HtmlConverter.ConvertToElements(customPageHtml, properties)[0];
            }
            else
            {
                htmlContainer = (Div)HtmlConverter.ConvertToElements(customPageHtml)[0];
            }
            htmlContainer.SetFixedPosition(0, 0, page.GetPageSize().GetWidth());
            htmlContainer.SetHeight(page.GetPageSize().GetHeight());
            canvas.Add(htmlContainer);
        }

        private void AddDataBag(PdfDocument pdfDoc, string dataBag)
        {
            PdfAcroForm form = PdfAcroForm.GetAcroForm(pdfDoc, true);
            PdfFormField field = PdfFormField.CreateText(pdfDoc, new Rectangle(0, 0, 100, 100), "databag", dataBag);
            field.SetVisibility(PdfFormField.HIDDEN);
            form.AddField(field);
        }

        private byte[] GetSealedBytes(byte[] bytesToSeal)
        {
            string provider = ConfigurationManager.AppSettings["AATLProviderName"];
            switch (provider.ToLower())
            {
                case "globalsign":
                    return new GlobalSign().Seal(bytesToSeal);
                default:
                    throw new Exception("Provider not supported");
            }
        }
    }
}
