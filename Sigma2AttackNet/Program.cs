using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection;
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
            [Option('c',"category-url", Required = false, HelpText = "URL with MITRE matrix")]
            public string CategoryMatrix { get; set; }
            [Option('d', "rules-directory", Required = true, HelpText = "Directory to read rules from")]
            public string RulesDirectory { get; set; }
            [Option('o', "out-file", Required = false, HelpText = "File to write the JSON layer to")]
            public string OutFile { get; set; } = "sigma-coverage.json";
            [Option('n', "no-comment", Required = false, HelpText = "Don't store rule names in comments")]
            public bool NoComment { get; set; } = false;
            [Option('w', "warning", Required = false, HelpText = "Check for ATT&CK technique and tactic mismatch")]
            public bool Warning { get; set; } = false;
        }
        public static void Main(string[] args)
        {
            var assembly = Assembly.GetExecutingAssembly();
            var resourceStream = assembly.GetManifestResourceStream("Sigma2AttackNet.config.json");
            StreamReader reader = new StreamReader(resourceStream);
            JObject temp = JsonConvert.DeserializeObject<JObject>(reader.ReadToEnd());
            var warnings = new List<string>();
            Dictionary<string, List<string>> techs = new Dictionary<string, List<string>>();
            int ruleCount = 0;
            int gradientMax = 0;
            Console.WriteLine(" ");
            Console.WriteLine($"S2AN by 3CORESec - {temp["repo_url"]}");
            Console.WriteLine(" ");
            Parser.Default.ParseArguments<Options>(args)
                .WithParsed(o =>
                {
                    Dictionary<string, List<string>> matrix = new Dictionary<string, List<string>>();
                    if (o.CategoryMatrix == null)
                    {
                        o.CategoryMatrix = temp["category_matrix_url"]?.ToString();
                    }
                    if (o.Warning)
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
                        }
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
                            if (o.Warning)
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

                                        if (category != null && o.Warning)
                                        {
                                            try
                                            {
                                                if (!(matrix.ContainsKey(techniqueId) && matrix[techniqueId].Contains(category)))
                                                    warnings.Add($"MITRE ATT&CK technique ({techniqueId}) and tactic ({category}) mismatch in rule: {ruleFile.Split("\\").Last()}");
                                            }
                                            catch (Exception)
                                            {
                                                // ignored
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
                        version = "4.1",
                        techniques = entries
                    }, Formatting.Indented, new JsonSerializerSettings
                    {
                        NullValueHandling = NullValueHandling.Ignore
                    }));
                    Console.WriteLine($"[*] Layer file written in {o.OutFile}");
                    if (warnings.Any())
                    {
                        Console.WriteLine(" ");
                        Console.WriteLine("Attention - mismatch between technique and tactic has been detected!");
                    }
                    warnings.ForEach(Console.WriteLine);
                });
        }
    }
}
