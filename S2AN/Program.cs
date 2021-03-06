﻿using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Text.RegularExpressions;
using CommandLine;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using YamlDotNet.Core;
using Parser = CommandLine.Parser;

namespace S2AN
{
    public class Program
    {
        public class Options
        {
            [Option('c', "category-url", Required = false, HelpText = "URL with MITRE matrix")]
            public string MitreMatrix { get; set; }
            [Option('d', "rules-directory", Required = true, HelpText = "Directory to read rules from")]
            public string RulesDirectory { get; set; }
            [Option('o', "out-file", Required = false, HelpText = "File to write the JSON layer to")]
            public string OutFile { get; set; } = ".json";
            [Option('n', "no-comment", Required = false, HelpText = "Don't store rule names in comments")]
            public bool NoComment { get; set; } = false;
            [Option('w', "warning", Required = false, HelpText = "Check for ATT&CK technique and tactic mismatch")]
            public bool Warning { get; set; } = false;
            [Option('s', "suricata", Required = false, HelpText = "Enable Suricata signature parsing")]
            public bool Suricata { get; set; } = false;

        }
        //Matrix to search for mismatches in case of w option
        static Dictionary<string, List<string>> mismatchSearchMatrix = new Dictionary<string, List<string>>();
        //List of mismatch warnings
        static List<string> mismatchWarnings = new List<string>();
        //List of techniques
        static Dictionary<string, List<string>> techniques = new Dictionary<string, List<string>>();
        /// <summary>
        /// for each file that contains tags, adds the file name to the techniques map for key technique.
        /// Also if warning flag is on, searches, if any, a given category group ON TOP of a single OR group of techniques.
        /// these category groups are reset whenever a new technique category entry is found, and this new group will be applied to the following technique group and so forth.
        /// </summary>
        /// <param name="args"></param>
        public static void Main(string[] args)
        {

            int ruleCount = 0;
            int gradientMax = 0;
            Parser.Default.ParseArguments<Options>(args)
                .WithParsed(o =>
                {
                    LoadConfig(o);
                    if (!o.Suricata)
                    {
                        LoadMismatchSearchMatrix(o);
                        foreach (var ruleFilePath in Directory.EnumerateFiles(o.RulesDirectory, "*.yml", SearchOption.AllDirectories))
                        {
                            try
                            {
                                var dict = DeserializeYamlFile(ruleFilePath, o);
                                if (dict != null && dict.ContainsKey("tags"))
                                {
                                    ruleCount++;
                                    var tags = dict["tags"];
                                    var categories = new List<string>();
                                    string lastEntry = null;
                                    foreach (string tag in tags)
                                    {
                                        //If its the technique id entry, then this adds the file name to the techniques map
                                        if (tag.ToLower().StartsWith("attack.t"))
                                        {
                                            var techniqueId = tag.Replace("attack.", "").ToUpper();
                                            if (!techniques.ContainsKey(techniqueId))
                                                techniques[techniqueId] = new List<string>();
                                            techniques[techniqueId].Add(ruleFilePath.Split("\\").Last());
                                            if (techniques.Count > gradientMax)
                                                gradientMax = techniques.Count;
                                            //then if there are any categories so far, it checks for a mismatch for each one
                                            if (categories.Count > 0 && o.Warning)
                                            {
                                                foreach (string category in categories)
                                                    if (!(mismatchSearchMatrix.ContainsKey(techniqueId) && mismatchSearchMatrix[techniqueId].Contains(category)))
                                                        mismatchWarnings.Add($"MITRE ATT&CK technique ({techniqueId}) and tactic ({category}) mismatch in rule: {ruleFilePath.Split("\\").Last()}");
                                            }
                                        }
                                        else
                                        {
                                            //if its the start of a new technique block, then clean categories and adds first category
                                            if (lastEntry == null || lastEntry.StartsWith("attack.t"))
                                                categories = new List<string>();
                                            categories.Add(
                                                tag.Replace("attack.", "")
                                                .Replace("_", "-")
                                                .ToLower());
                                        }
                                        lastEntry = tag;
                                    }
                                }
                            }
                            catch (YamlException e)
                            {
                                Console.Error.WriteLine($"Ignoring rule {ruleFilePath} (parsing failed)");
                            }
                        }

                        WriteSigmaFileResult(o, gradientMax, ruleCount, techniques);
                        PrintWarnings();
                    }
                    else
                    {

                        List<Dictionary<string, List<string>>> res = new List<Dictionary<string, List<string>>>();

                        foreach (var ruleFilePath in Directory.EnumerateFiles(o.RulesDirectory, "*.rules", SearchOption.AllDirectories))
                        {
                            res.Add(ParseRuleFile(ruleFilePath));
                        }

                        WriteSuricataFileResult(o,
                            res
                                .SelectMany(dict => dict)
                                .ToLookup(pair => pair.Key, pair => pair.Value)
                                .ToDictionary(group => group.Key,
                                              group => group.SelectMany(list => list).ToList()));
                    }

                });
        }
        /// <summary>
        /// Prints config.json params and then adds default MITRE matrix url in case it's missing from options
        /// </summary>
        /// <param name="o"></param>
        public static void LoadConfig(Options o)
        {
            //Write all the blah blah
            var assembly = Assembly.GetExecutingAssembly();
            var resourceStream = assembly.GetManifestResourceStream("S2AN.config.json");
            StreamReader reader = new StreamReader(resourceStream);
            var config = JsonConvert.DeserializeObject<JObject>(reader.ReadToEnd());
            Console.WriteLine($"\n S2AN by 3CORESec - {config["repo_url"]}\n");
            //Load default configuration for ATT&CK technique and tactic mismatch search
            if (o.MitreMatrix == null)
            {
                o.MitreMatrix = config["category_matrix_url"]?.ToString();
            }
        }
        /// <summary>
        /// If warning flag in options is true, then mismatchSearchMatrix is loaded with information from the Mitre matrix url
        /// </summary>
        /// <param name="o"></param>
        public static void LoadMismatchSearchMatrix(Options o)
        {
            if (o.Warning)
            {
                foreach (var x in (JsonConvert.DeserializeObject<JObject>(new WebClient().DownloadString(o.MitreMatrix))["objects"] as JArray)!
                    .Where(x => x["external_references"] != null && x["external_references"].Any(y => y["source_name"] != null && x["kill_chain_phases"] != null)))
                {
                    var techId = x["external_references"]
                        .First(x => x["source_name"].ToString() == "mitre-attack")["external_id"]
                        .ToString();
                    if (!mismatchSearchMatrix.ContainsKey(techId))
                        mismatchSearchMatrix.Add(techId,
                            x["kill_chain_phases"]!.Select(x => x["phase_name"].ToString()).ToList()
                        );
                    else
                    {
                        mismatchSearchMatrix[techId] = mismatchSearchMatrix[techId].Concat(x["kill_chain_phases"]!.Select(x => x["phase_name"].ToString())).ToList();
                    }
                }
            }
        }
        /// <summary>
        /// Prints warnings in mismatchWarnings
        /// </summary>
        public static void PrintWarnings()
        {
            if (mismatchWarnings.Any())
            {
                Console.WriteLine(" ");
                Console.WriteLine("Attention - mismatch between technique and tactic has been detected!");
            }
            mismatchWarnings.ForEach(Console.WriteLine);
        }
        /// <summary>
        /// Writes sigma entries tag mappings to file
        /// </summary>
        /// <param name="o"></param>
        /// <param name="gradientMax"></param>
        /// <param name="ruleCount"></param>
        /// <param name="entries"></param>
        public static void WriteSigmaFileResult(Options o, int gradientMax, int ruleCount, Dictionary<string, List<string>> techniques)
        {
            try
            {
                var entries = techniques
                    .ToList()
                    .Select(entry => new
                    {
                        techniqueID = entry.Key,
                        score = entry.Value.Count,
                        comment = (o.NoComment) ? null : string.Join(Environment.NewLine, entry.Value.Select(x => x.Split("/").Last()))
                    });

                string filename = o.OutFile.EndsWith(".json") ? "sigma-coverage.json" : $"{o.OutFile}.json";
                File.WriteAllText(filename, JsonConvert.SerializeObject(new
                {
                    domain = "mitre-enterprise",
                    name = "Sigma signatures coverage",
                    gradient = new
                    {
                        colors = new[] { "#a0eab5", "#0f480f" },
                        maxValue = gradientMax,
                        minValue = 0
                    },
                    version = "4.2",
                    techniques = entries
                }, Formatting.Indented, new JsonSerializerSettings
                {
                    NullValueHandling = NullValueHandling.Ignore
                }));
                Console.WriteLine($"[*] Layer file written in {filename} ({ruleCount} rules)");
            }
            catch (Exception e)
            {
                Console.WriteLine("Problem writing to file: " + e.Message);
            }
        }
        /// <summary>
        /// Writes suricata result entries mappings to file
        /// </summary>
        /// <param name="o"></param>
        /// <param name="gradientMax"></param>
        /// <param name="ruleCount"></param>
        /// <param name="entries"></param>
        public static void WriteSuricataFileResult(Options o, Dictionary<string, List<string>> techniques)
        {
            try
            {

                var entries = techniques
                    .ToList()
                    .Select(entry => new
                    {
                        techniqueID = entry.Key,
                        score = entry.Value.Count,
                        comment = (o.NoComment) ? null : string.Join(Environment.NewLine, entry.Value.Select(x => x.Split("/").Last()))
                    });

                string filename = o.OutFile.EndsWith(".json") ? "suricata-coverage.json" : $"{o.OutFile}.json";
                File.WriteAllText(filename, JsonConvert.SerializeObject(new
                {
                    domain = "mitre-enterprise",
                    name = "Suricata rules coverage",
                    gradient = new
                    {
                        colors = new[] { "#a0eab5", "#0f480f" },
                        maxValue = techniques
                            .Values
                            .Max(x => x.Count),
                        minValue = 0
                    },
                    version = "4.2",
                    techniques = entries
                }, Formatting.Indented, new JsonSerializerSettings
                {
                    NullValueHandling = NullValueHandling.Ignore
                }));
                Console.WriteLine($"[*] Layer file written in {filename} ({entries.Count()} techniques covered)");
            }
            catch (Exception e)
            {
                Console.WriteLine("Problem writing to file: " + e.Message);
            }
        }
        public static Dictionary<string, dynamic> DeserializeYamlFile(string ruleFilePath, Options o)
        {
            var contents = File.ReadAllText(ruleFilePath);
            if (!contents.Contains("tags"))
            {
                Console.WriteLine($"Ignoring rule {ruleFilePath} (no tags)");
                return null;
            }
            if (o.Warning)
                contents = contents.Replace(Environment.NewLine + Environment.NewLine,
                        Environment.NewLine)
                    .Remove(0, contents.IndexOf("tags", StringComparison.Ordinal));
            if (contents.Contains("---"))
                contents = contents.Remove(contents.IndexOf("---", StringComparison.Ordinal));
            var deserializer = new YamlDotNet.Serialization.Deserializer();
            var dict = deserializer.Deserialize<Dictionary<string, dynamic>>(contents);
            return dict;
        }
        /// <summary>
        /// for a given file, searches for lines containing both a msg and a mitre_technique_id, whenever a pair is found, it's added to the result
        /// </summary>
        /// <param name="ruleFilePath"></param>
        /// <returns></returns>
        public static Dictionary<string, List<string>> ParseRuleFile(string ruleFilePath)
        {
            Dictionary<string, List<string>> res = new Dictionary<string, List<string>>();
            var contents = new StringReader(File.ReadAllText(ruleFilePath));
            string line = contents.ReadLine();
                while (line != null)
                {
                    try
                    {
                        //if the line contains a mitre_technique
                        if (line.Contains("mitre_technique_id "))
                        {
                            List<string> techniques = new List<string>();
                            //get all indexes from all technique ids and add them all to a list
                            IEnumerable<int> indexes = Regex.Matches(line, "mitre_technique_id ").Cast<Match>().Select(m => m.Index + "mitre_technique_id ".Length);
                            foreach (int index in indexes) 
                                techniques.Add(line.Substring(index, line.IndexOfAny(new [] { ',', ';' }, index) - index));
                            int head = line.IndexOf("msg:\"") + "msg:\"".Length;
                            int tail = line.IndexOf("\"", head);
                            string msg = line.Substring(head, tail - head);
                            head = line.IndexOf("sid:") + "sid:".Length;
                            tail = line.IndexOfAny(new char[] { ',', ';' }, head);
                            string sid = line.Substring(head, tail - head);
                            //for each found technique add the sid along with the message to the content
                            foreach( string technique in techniques)
                            {
                                if (res.ContainsKey(technique))
                                    res[technique].Add($"{sid} - {msg}");
                                else
                                    res.Add(technique, new List<string> { $"{sid} - {msg}" });
                            }
                        }
                        line = contents.ReadLine();
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine(line);
                        Console.WriteLine(e.Message);
                        line = contents.ReadLine();
                }
                }
                return res;
            }
        }
    }
