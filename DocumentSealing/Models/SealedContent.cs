using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace DocumentSealing.Models
{
    public class SealedContent
    {
        [JsonProperty("encoding")]
        public string Encoding { get; set; }

        [JsonProperty("content")]
        public string Content { get; set; }
    }
}