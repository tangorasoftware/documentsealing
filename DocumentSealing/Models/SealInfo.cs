using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace DocumentSealing.Models
{
    public class SealInfo
    {
        public string DataBag { get; set; }
        public string Creator { get; set; }
        public Document Document { get; set; }
        public string CustomPageHtml { get; set; }
    }
}