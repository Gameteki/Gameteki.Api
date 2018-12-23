namespace CrimsonDev.Gameteki.Api.Models.Api
{
    using System;
    using System.Collections.Generic;

    public class ApiRestrictedListEntry
    {
        public int Id { get; set; }
        public string Version { get; set; }
        public DateTime Date { get; set; }

        public List<string> MeleeCards { get; set; }
        public List<string> JoustCards { get; set; }
    }
}