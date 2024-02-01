import click
import copy
import os
import re
import yaml

from logger import Logger

logger = Logger().logger
    
class AuditorConfig:
    
    def __init__(self, template, template_dir_path):
        self.template = template
        self.template_dir_path = template_dir_path
        self.default_var_sub = ".+"
        self.regex_var_subs = dict()
        self.datatypes = dict()
        self.variables = dict()
        self.ignore_list = list()
        self._skip = list()
        
    @property
    def skip(self):
        return self._skip
        
    def add_regex_sub(self, var: str, sub: str) -> None:
        self.regex_var_subs.update({var: sub})
        
    def add_ignore_lines(self, context="config", *lines) -> None:
        if context == "template":
            self._skip += list
        elif context == "config":
            self.ignore_list += list
        
    def read_datatypes(self, filepath: str) -> None:
        with open(filepath, "r") as f:
            content = f.read()
            self.datatypes = yaml.load(content, Loader=yaml.Loader)
            
    def read_variables(self, filepath: str) -> None:
     
        with open(filepath, "r") as f:
            content = f.read()
            self.variables = yaml.load(content, Loader=yaml.Loader)[self.template.split(".")[0]]
        for var in self.variables:
            var_regex = r'{{\s{0,}' + var + r'\s{0,}}}'
            regex_sub = self.variables[var]
            if regex_sub in self.datatypes:
                regex_sub = self.datatypes[regex_sub]
            self.add_regex_sub(var_regex, regex_sub)
            
    def read_template_ignore(self, filepath: str) -> None:
        with open(filepath, "r") as f:
            content = f.read()
            parsed = yaml.load(content, Loader=yaml.Loader)
            if self.template.split(".")[0] in parsed:
                self._skip += parsed[self.template.split(".")[0]]
            if "general" in parsed:
                self._skip += parsed["general"]
                
    def read_config_ignore(self, filepath: str) -> None:
        with open(filepath, "r") as f:
            content = f.read()
            parsed = yaml.load(content, Loader=yaml.Loader)
            if self.template.split(".")[0] in parsed:
                self.ignore_list += parsed[self.template.split(".")[0]]
            if "general" in parsed:
                self.ignore_list += parsed["general"]
                
    def read_settings(self, config_dir_path="config"):
        self.read_datatypes(f"{config_dir_path}/datatypes.yaml")
        self.read_variables(f"{config_dir_path}/variables.yaml")
        self.read_template_ignore(f"{config_dir_path}/ignore_in_template.yaml")
        self.read_config_ignore(f"{config_dir_path}/ignore_in_config.yaml")
        
        
class Jinja2GoldenConfigParser:
    
    def __init__(self, AuditorConfig):
        self.parsed = {}
        self.conditionals = {}
        self.regex_line_index = {}
        self.config = AuditorConfig
        
    def load_template(self) -> (dict, dict):
        template_path = self.config.template_dir_path + "/" + self.config.template
        with open(template_path, "r") as f:
            template = f.read()
        is_conditional = False
        is_looped = False
        conditional_id = -1
        option = 0
        parent = None
        for i, line in enumerate(template.splitlines()):
            line = line.rstrip()
            # Initial checks
            if self._skip_jinja2_line(line):
                continue
            if line in self.parsed:
                self.parsed[line]["lines"].append(i)
            # Parse line  
            if re.match(r"{%\s+if.+%}", line.strip()) is not None:
                is_conditional = True
                conditional_id += 1
            elif re.match(r"{%\s+elif.+%}", line.strip()) is not None:
                option += 1
            elif re.match(r"{%\s+else\s+%}", line.strip()) is not None:
                option += 1
            elif re.match(r"{%\s+endif\s+%}", line.strip()) is not None:
                is_conditional = False
                option = 0
            elif re.match(r"{%\s+for[a-zA-Z0-9_\.\s]+%}", line.strip()) is not None:
                is_looped = True
            elif re.match(r"{%\s+endfor\s+%}", line.strip()) is not None:
                is_looped = False
            else:
                if line.lstrip() == line:
                    parent = None
                regex = self._convert_to_regex(line)
                # Find and register potential conflicts
                if regex not in self.regex_line_index:
                    self.regex_line_index[regex] = {"count": 0}
                self.regex_line_index[regex]["count"] += 1
                if "has_looped" not in self.regex_line_index[regex] or not self.regex_line_index[regex]["has_looped"]:
                    self.regex_line_index["has_looped"] = is_looped
                if "has_conditional" not in self.regex_line_index[regex] or not self.regex_line_index[regex]["has_conditional"]:
                    self.regex_line_index[regex]["has_conditional"] = is_conditional
                self.parsed[line] = {
                    "looped": is_looped,
                    "conditional": is_conditional,
                    "lines": [i],
                    "regex": regex,
                    "parent": parent,
                    "children": [],
                }
                if parent is None:
                    parent = line
                else:
                    self.parsed[parent]["children"].append(line)
                if is_conditional:
                    self.parsed[line]["conditional_id"] = conditional_id
                    self.parsed[line]["option"] = option
                    if conditional_id not in self.conditionals:
                        self.conditionals[conditional_id] = {}
                    if option not in self.conditionals[conditional_id]:
                        self.conditionals[conditional_id][option] = []
                    self.conditionals[conditional_id][option].append(line)
        return self.parsed, self.conditionals, self.regex_line_index
    
    def _skip_jinja2_line(self, line: str) -> bool:
        skip = self.config.skip
        for item in skip:
            if re.match(item, line) is not None:
                return True
        return False
    
    def _convert_to_regex(self, line: str) -> str:
        # Remove new lines and literalize "." for nested
        corrected = line.replace("\t", "")
        corrected = corrected.replace("\n", "")
        corrected = corrected.replace("\r", "")
        corrected = corrected.replace(".", "\.")
        corrected = corrected.replace("+", "\+")
        # Transform line to regex
        if "{{" in corrected:
            for var in self.config.regex_var_subs:
                sub = self.config.regex_var_subs[var]
                corrected = re.sub(var, sub, corrected)
                if sub in corrected:
                    break
            corrected = re.sub(r'{{[^{]+}}', self.config.default_var_sub, corrected)
        # corrected = corrected.replace(" ", "\s")
        corrected += '\r{0,}\n'
        return corrected
    
    
class Jinja2GoldenConfigAuditor:
    
    def __init__(self, GoldenConfigParser, AuditorConfig):
        self.template = GoldenConfigParser.parsed
        self.conditionals = GoldenConfigParser.conditionals
        self.regex_line_index = GoldenConfigParser.regex_line_index
        self.config = AuditorConfig

    def audit_file(self, filepath: str) -> dict:
        audit = {
            "missing": {},
            "extra": {},
        }
        with open(filepath, "r") as f:
            text = f.read()
            text += "\n" # temporary fix of bug
        index = self._index_lines(text)
        lines = [index[k][0] for k in index.keys()]
        handled_conditionals = []
        # MISSING AND EXTRA (IN TEMPLATE)
        for line in self.template:
            if self.template[line]["conditional"]:
                conditional_id = self.template[line]["conditional_id"] 
                if conditional_id in handled_conditionals:
                    continue
                audited, remove_lines = self._audit_conditionals(conditional_id, text, index)
                audit = self._merge_audits(audit, audited)
                handled_conditionals.append(conditional_id)
                lines = self._update_line_list(lines, remove_lines)
                continue
            regex = self.template[line]["regex"]
            matches = self._match_regex(regex, text)
            matched_lines = self._get_match_lines(matches, index)
            if len(matched_lines) > len(self.template[line]["lines"]) and not self.template[line]["looped"]:
                # Check for conflicting lines (same regex, diff var or conditional rules)
                if (self.regex_line_index[regex]["count"] <= len(matched_lines) or self.regex_line_index.get(regex).get("has_looped")):
                    lines = self._update_line_list(lines, matched_lines)
                    continue
                audit["extra"][line] = {
                    "lines": matched_lines,
                    "expected_count": len(self.template[line]["lines"]),
                    "actual_count": len(matched_lines),
                }
                lines = self._update_line_list(lines, matched_lines)
            elif len(matches) == 0 and not self.template[line]["looped"]:
                audit["missing"][line] = {
                    "line": self.template[line]["lines"][0],
                    "parent": self.template[line]["parent"],
                    "children": self.template[line]["children"]
                }
            else:
                lines = self._update_line_list(lines, matched_lines)
        # EXTRA (NOT IN TEMPLATE)
        extra_staging = {}
        for char_idx in index:
            lineno = index[char_idx][0]
            if lineno not in lines:
                continue
            remaining_line = index[char_idx][1]
            found_match = False
            for ignore in self.config.ignore_list:
                if re.match(ignore, remaining_line) is not None:
                    found_match = True
                    break
            if not found_match:
                if remaining_line not in extra_staging:
                    extra_staging[remaining_line] = []
                extra_staging[remaining_line].append(lineno)
        for staged_line in extra_staging:
            audit["extra"][staged_line] = {
                "lines": extra_staging[staged_line],
                "expected_count": 0,
                "actual_count": len(extra_staging[staged_line])
            }
        return {filepath: audit}
    
    
    def _diff_conditionals(self, conditional_id: int):
        block = self.conditionals[conditional_id]
        # Get unique for each option in conditional block
        lines = {}
        for option in block:
            for line in block[option]:
                if line not in lines:
                    lines[line] = []
                lines[line].append(option)
        diffed = {}
        for line in lines:
            if len(lines[line]) == 1:
                option = lines[line][0]
                if option not in diffed:
                    diffed[option] = []
                diffed[option].append(line)
        return diffed
    
    def _identify_option_block(self, conditional_id: int, text: str, index: dict):
        diffed = self._diff_conditionals(conditional_id)
        for option_id in diffed:
            for line in diffed[option_id]:
                regex = self.template[line]["regex"]
                matches = self._match_regex(regex, text)
                matched_lines = self._get_match_lines(matches, index)
                if len(matched_lines) > 0:
                    return option_id
        return None
    
    def _audit_conditionals(self, conditional_id: int, text: str, index: dict):
        option_block_id = self._identify_option_block(conditional_id, text, index)
        audit = {
            "missing": {},
            "extra": {}
        }
        remove_lines = []
        if option_block_id is None:
            return audit, remove_lines
        with open("debug.log", "a+") as f:
            f.write(str(conditional_id) + ", " + str(option_block_id))
            f.write("\n")
            f.write(str(self.conditionals))
            f.write("\n\n\n")
        for line in self.conditionals[conditional_id][option_block_id]:
            regex = self.template[line]["regex"]
            matches = self._match_regex(regex, text)
            matched_lines = self._get_match_lines(matches, index)
            if len(matched_lines) > len(self.template[line]["lines"]) and not self.template[line]["looped"]:
                audit["extra"][line] = {
                    "lines": matched_lines,
                    "expected_count": len(self.template[line]["lines"]),
                    "actual_count": len(matched_lines),
                }
                remove_lines += matched_lines
            elif len(matches) == 0 and not self.template[line]["looped"]:
                audit["missing"][line] = {
                    "line": self.template[line]["lines"][0],
                    "parent": self.template[line]["parent"],
                    "children": self.template[line]["children"]
                }
            else:
                remove_lines += matched_lines
        return audit, remove_lines
        
    def audit_files(self, filepaths: list, template: dict) -> dict:
        audits = {}
        for filepath in filepaths:
            audit = self.audit_file(filepath, template)
            audits.update(audit)
        return audits
    
    def audit_dir(self, dirpath: str, template: dict) -> dict:
        filepaths = [f for f in os.listdir(dirpath) if os.path.isfile(os.path.join(dirpath, f))]
        audits = self.audit_files(filepaths, template)
        return audits
    
    def _match_regex(self, regex: str, text: str) -> list:
        matches = [(m.start(0), m.end(0)) for m in re.finditer(regex, text)]
        return matches

    def _index_to_lineno_conversion(self, index: tuple, lines_index: dict) -> int:
        if index in lines_index:
            return lines_index[index][0]
        return -1

    def _update_line_list(self, lines: list, remove: int | list) -> list:
        """Remove line numbers from line list"""
        lines_copy = copy.copy(lines)
        if type(remove) is list:
            for lineno in remove:
                try:
                    lines_copy.remove(lineno)
                except ValueError:
                    continue
        else:
            try:
                lines_copy.remove(remove)
            except ValueError:
                pass
        return lines_copy
        
    def _index_lines(self, text: str) -> dict:
        """Get line number / char position relationships
        and list of line noumbers"""
        index = {}
        chars = 0
        for i, line in enumerate(text.splitlines()):
            index[chars] = (i, line)
            chars += (len(line) + 1)
        return index

    def _get_match_lines(self, matches: list, lines_index: dict) -> list:
        converted = []
        for match in matches:
            begin_index = match[0]
            lineno = self._index_to_lineno_conversion(begin_index, lines_index)
            # Right now, -1 usually means the match has unwanted spaces
            # so if a line number can't be found, it's skipped
            if lineno >= 0: 
                converted.append(lineno)
        return converted

    def _merge_audits(self, *audits):
        master = dict()
        for i, audit in enumerate(audits):
            if i == 0:
                master.update(audit)
            else:
                master["extra"].update(audit["extra"])
                master["missing"].update(audit["missing"])
        return master
            
            
class GoldenConfigAuditor:
    
    def __init__(self, AuditorConfig):
        self.config = AuditorConfig
        self.parser = Jinja2GoldenConfigParser(self.config)
        self.parser.load_template()
        self.auditor = Jinja2GoldenConfigAuditor(self.parser, self.config)
        
    @staticmethod
    def output_audit(audit, dirpath=""):
        for filepath in audit:
            audit_filename = filepath.split("/")[-1].split(".")[0] + "_audit.yaml"
            if dirpath != "":
                write_path = dirpath + "/" + audit_filename
            else:
                write_path = audit_filename
            with open(write_path, "w+") as output:
                reformatted = {
                    "FILE AUDITED": filepath,
                    "MISSING": {
                        "total": len(audit[filepath]["missing"]),
                        "lines": audit[filepath]["missing"]
                    }, 
                    "NOT COMPLIANT": {
                        "total": len(audit[filepath]["extra"]),
                        "lines": audit[filepath]["extra"]
                    }
                }
                yaml.dump(reformatted, output)


@click.command()
@click.option("-cD", "--config-dir", default="config", help="Path to directory with config files")
@click.option("-tD", "--template-dir", default="templates", help="Path to directory with template")
@click.option("-t", "--template", help="The name of your golden config template (including .j2)")
@click.option("-aF", "--audit-file", default="", help="Path to file being audited")
@click.option("-aD", "--audit-dir", default="", help="Path to directory of files being audited")
@click.option("-oD", "--output-dir", default="", help="Path to directory where audit(s) should be outputed")
def audit(config_dir, template_dir, template, audit_file, audit_dir, output_dir):
    config = AuditorConfig(template, template_dir)
    config.read_settings(config_dir)
    control = GoldenConfigAuditor(config)
    if audit_file != "":
        audit = control.auditor.audit_file(audit_file)
    else:
        audit = control.auditor.audit_dir(audit_dir)
    control.output_audit(audit, output_dir)
    click.echo("Completed audit")
    
    
if __name__ == "__main__":
    audit()
