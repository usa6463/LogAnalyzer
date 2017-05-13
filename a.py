import re

fields = {
        'date': '(?P<date>\d+[-\d+]+',
        'time': '[\d+:]+)[.\d]*?', # TODO should not assume date & time will be together not sure how to fix ATM.
        'cs-uri-stem': '(?P<path>/\S*)',
        'cs-uri-query': '(?P<query_string>\S*)',
        'c-ip': '"?(?P<ip>[\w*.:-]*)"?',
        'cs(User-Agent)': '(?P<user_agent>".*?"|\S*)',
        'cs(Referer)': '(?P<referrer>\S+)',
        'sc-status': '(?P<status>\d+)',
        'sc-bytes': '(?P<length>\S+)',
        'cs-host': '(?P<host>\S+)',
        'cs-username': '(?P<userid>\S+)',
        'time-taken': '(?P<generation_time_secs>[.\d]+)'
    }

line = '2015-12-21 11:59:58 172.17.100.8 GET /images/orderpagecvr/CVR-S/stone/stone-cvrop-default.jpg - 443 - 75.89.22.249 Mozilla/5.0 (iPhone; CPU iPhone OS 7_1_2 like Mac OS X) AppleWebKit/537.51.2 (KHTML, like Gecko) Mobile/11D257 https://REDACTED.com/Express/default.aspx?partnerId=INBOXDOLLARSSTSP00007&partnerOrderId=ibd13250917x1387513028&t=Z4QGuPtTjAEFpBa87eTFGbbmAcDTErHb 200 0 0 0'

p = re.compile(fields['c-ip'])
t = p.findall(line)[0]
print(t)



class W3cExtendedFormat(RegexFormat):

    FIELDS_LINE_PREFIX = '#Fields: '

    fields = {
        'date': '(?P<date>\d+[-\d+]+',
        'time': '[\d+:]+)[.\d]*?', # TODO should not assume date & time will be together not sure how to fix ATM.
        'cs-uri-stem': '(?P<path>/\S*)',
        'cs-uri-query': '(?P<query_string>\S*)',
        'c-ip': '"?(?P<ip>[\w*.:-]*)"?',
        'cs(User-Agent)': '(?P<user_agent>".*?"|\S*)',
        'cs(Referer)': '(?P<referrer>\S+)',
        'sc-status': '(?P<status>\d+)',
        'sc-bytes': '(?P<length>\S+)',
        'cs-host': '(?P<host>\S+)',
        'cs-username': '(?P<userid>\S+)',
        'time-taken': '(?P<generation_time_secs>[.\d]+)'
    }

    def __init__(self):
        super(W3cExtendedFormat, self).__init__('w3c_extended', None, '%Y-%m-%d %H:%M:%S')

    def check_format(self, file):
        self.create_regex(file)

        # if we couldn't create a regex, this file does not follow the W3C extended log file format
        if not self.regex:
            try:
                file.seek(0)
            except IOError:
                pass

            return

        first_line = file.readline()

        try:
            file.seek(0)
        except IOError:
            pass

        return self.check_format_line(first_line)

    def create_regex(self, file):
        fields_line = None
        if config.options.w3c_fields:
            fields_line = config.options.w3c_fields

        # collect all header lines up until the Fields: line
        # if we're reading from stdin, we can't seek, so don't read any more than the Fields line
        header_lines = []
        while fields_line is None:
            line = file.readline().strip()

            if not line:
                continue

            if not line.startswith('#'):
                break

            if line.startswith(W3cExtendedFormat.FIELDS_LINE_PREFIX):
                fields_line = line
            else:
                header_lines.append(line)

        if not fields_line:
            return

        # store the header lines for a later check for IIS
        self.header_lines = header_lines

        # Parse the 'Fields: ' line to create the regex to use
        full_regex = []

        expected_fields = type(self).fields.copy() # turn custom field mapping into field => regex mapping

        # if the --w3c-time-taken-millisecs option is used, make sure the time-taken field is interpreted as milliseconds
        if config.options.w3c_time_taken_in_millisecs:
            expected_fields['time-taken'] = '(?P<generation_time_milli>[\d.]+)'

        for mapped_field_name, field_name in config.options.custom_w3c_fields.iteritems():
            expected_fields[mapped_field_name] = expected_fields[field_name]
            del expected_fields[field_name]

        # add custom field regexes supplied through --w3c-field-regex option
        for field_name, field_regex in config.options.w3c_field_regexes.iteritems():
            expected_fields[field_name] = field_regex

        # Skip the 'Fields: ' prefix.
        fields_line = fields_line[9:].strip()
        for field in re.split('\s+', fields_line):
            try:
                regex = expected_fields[field]
            except KeyError:
                regex = '(?:".*?"|\S+)'
            full_regex.append(regex)
        full_regex = '\s+'.join(full_regex)

        logging.debug("Based on 'Fields:' line, computed regex to be %s", full_regex)

        self.regex = re.compile(full_regex)

    def check_for_iis_option(self):
        if not config.options.w3c_time_taken_in_millisecs and self._is_time_taken_milli() and self._is_iis():
            logging.info("WARNING: IIS log file being parsed without --w3c-time-taken-milli option. IIS"
                         " stores millisecond values in the time-taken field. If your logfile does this, the aforementioned"
                         " option must be used in order to get accurate generation times.")

    def _is_iis(self):
        return len([line for line in self.header_lines if 'internet information services' in line.lower() or 'iis' in line.lower()]) > 0

    def _is_time_taken_milli(self):
        return 'generation_time_milli' not in self.regex.pattern