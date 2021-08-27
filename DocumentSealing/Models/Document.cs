using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace DocumentSealing.Models
{
    public class Document
    {
        public string Filename { get; set; }
        public string FileContent { get; set; }
    }
}