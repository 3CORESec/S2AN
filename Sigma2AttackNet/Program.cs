using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using CommandLine;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using YamlDotNet.Core;
using Parser = CommandLine.Parser;

namespace Sigma2AttackNet
{
    public class Program
    {
        public class Options
        {

            [Option("category-url", Required = false, HelpText = "Url with mitre matrix")]
            public string CategoryMatrix { get; set; } = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json";

            [Option('d', "rules-directory", Required = true, HelpText = "Directory to read rules from")]
            public string RulesDirectory { get; set; }

            [Option('o', "out-file", Required = false, HelpText = "File to write the JSON layer to")]
            public string OutFile { get; set; } = "sigma-coverage.json";

            [Option("no-comment", Required = false, HelpText = "Don't store rule names in comments")]
            public bool NoComment { get; set; } = false;

            [Option("no-warning", Required = false, HelpText = "Don't check techniques")]
            public bool NoWarning { get; set; } = false;
        }
        public static void Main(string[] args)
        {
            var warnings = new List<string>();
            Dictionary<string, List<string>> techs = new Dictionary<string, List<string>>();
            int ruleCount = 0;
            int gradientMax = 0;
            Parser.Default.ParseArguments<Options>(args)
                .WithParsed(o =>
                {

                Dictionary<string, List<string>> matrix = new Dictionary<string, List<string>>();
                    if (!o.NoWarning)
                    {
                        var _matrix = (JsonConvert.DeserializeObject<JObject>(new WebClient().DownloadString(o.CategoryMatrix))["objects"] as JArray)!
                            .Where(x => x["external_references"] != null && x["external_references"].Any(y => y["source_name"] != null && x["kill_chain_phases"] != null));
                        
                        foreach (var x in _matrix)
                        {

                            var techId = x["external_references"]
                                .First(x => x["source_name"].ToString() == "mitre-attack")["external_id"]
                                .ToString();

                            if (!matrix.ContainsKey(techId))
                            matrix.Add(techId,
                                x["kill_chain_phases"]!.Select(x => x["phase_name"].ToString()).ToList()
                            );
                            else
                            {
                                matrix[techId] = matrix[techId].Concat(x["kill_chain_phases"]!.Select(x => x["phase_name"].ToString())).ToList();
                            }
                        };
    
                    }

                    foreach (var ruleFile in Directory.EnumerateFiles(o.RulesDirectory, "*.yml", SearchOption.AllDirectories))
                    {
                        try
                        {
                            string contents = File.ReadAllText(ruleFile);
                            if (!contents.Contains("tags"))
                            {
                                Console.WriteLine($"Ignoring rule {ruleFile} (no tags)");
                                continue;
                            }

                            string title = null;

                            if (!o.NoWarning)
                                try 
                                { 
                                    title = new string(contents.TakeWhile(c => c != '\n').ToArray()).Split(":")[1];
                                }
                                catch (Exception e)
                                {
                                    Console.WriteLine("unable to parse a rule title");
                                }

                            contents = contents.Replace(Environment.NewLine + Environment.NewLine,
                                        Environment.NewLine)
                                    .Remove(0, contents.IndexOf("tags", StringComparison.Ordinal));
                            if (contents.Contains("---"))
                                contents = contents.Remove(contents.IndexOf("---", StringComparison.Ordinal));
                            var deserializer = new YamlDotNet.Serialization.Deserializer();
                            var dict = deserializer.Deserialize<Dictionary<string, dynamic>>(contents);
                            if (dict.ContainsKey("tags"))
                            {
                                var tags = dict["tags"];
                                string category = null;
                                foreach (string tag in tags)
                                {
                                    if (tag.ToLower().StartsWith("attack.t"))
                                    {
                                        var techniqueId = tag.Replace("attack.", "").ToUpper();
                                        ruleCount++;
                                        if (!techs.ContainsKey(techniqueId))
                                            techs[techniqueId] = new List<string>();
                                        techs[techniqueId].Add(ruleFile.Split("\\").Last());
                                        if (techs.Count > gradientMax)
                                            gradientMax = techs.Count;

                                        if (category != null && !o.NoWarning)
                                        {
                                            try
                                            {
                                                if (!(matrix.ContainsKey(techniqueId) && matrix[techniqueId].Contains(category)))
                                                    warnings.Add($"MITRE technique ({techniqueId}) and tactic ({category}) mismatch in rule: {title}");
                                            }
                                            catch (Exception)
                                            {

                                            }
                                        }
                                    }
                                    else
                                    {
                                        category = tag.Replace("attack.", "")
                                        .Replace("_", "-")
                                        .ToLower();


                                    }
                                }
                            }
                        }
                        catch (YamlException e)
                        {
                            Console.Error.WriteLine($"Ignoring rule {ruleFile} (parsing failed)");
                        }
                    }
                    var entries = techs
                        .ToList()
                        .Select(entry => new
                        {
                            techniqueID = entry.Key,
                            score = entry.Value.Count,
                            comment = (o.NoComment) ? null : string.Join(Environment.NewLine, entry.Value.Select(x => x.Split("/").Last()))
                        });

                    File.WriteAllText(o.OutFile.EndsWith(".json") ? o.OutFile : $"{o.OutFile}.json", JsonConvert.SerializeObject(new
                    {
                        domain = "mitre-enterprise",
                        name = "Sigma rules coverage",
                        gradient = new
                        {
                            colors = new[] { "#a0eab5", "#0f480f" },
                            maxValue = gradientMax,
                            minValue = 0
                        },
                        version = "3.0",
                        techniques = entries
                    }, Formatting.Indented, new JsonSerializerSettings
                    {
                        NullValueHandling = NullValueHandling.Ignore
                    }));
                    Console.WriteLine($"[*] Layer file written in {o.OutFile} ({ruleCount} rules)");
                    warnings.ForEach(Console.WriteLine);
                });
        }
    }
}
