"""
    author: 
    hasbiyama (@3xploitZero)
    github.com/hasbiyama

"""

from constants import *

# Class to adjust the time to the local (machine) time
class TimeAdjuster:
    def adjust_time_to_gmt(self, time_str):
        return self.adjust_time_to_timezone(time_str, 'Etc/GMT')

    def adjust_time_to_pdt(self, time_str):
        return self.adjust_time_to_timezone(time_str, 'US/Pacific')

    def adjust_time_to_timezone(self, time_str, timezone):
        match = re.search(r'(\d{1,2}) (\w{3}) (\d{4}) (\d{1,2}):(\d{2}):(\d{2})', time_str)
        day, month, year, hour, minute, second = match.groups()

        month = month_dict[month]

        time_obj = datetime.datetime(int(year), month, int(day), int(hour), int(minute), int(second))

        tz = pytz.timezone(timezone)

        adjusted_time_obj = tz.localize(time_obj)

        # Incorporate the local machine's time zone
        local_tz = datetime.datetime.now(datetime.timezone.utc).astimezone().tzinfo
        adjusted_time_obj = adjusted_time_obj.astimezone(local_tz)

        return adjusted_time_obj.strftime("%a, %d %b %Y %H:%M:%S %z")

    def adjust_time_raw_email(self, time_str):
        time_format = "%Y-%m-%d %H:%M:%S"
        time_obj = datetime.datetime.strptime(str(time_str), time_format)

        adjusted_time = time_obj.replace(tzinfo=datetime.timezone.utc)

        local_time = adjusted_time.astimezone()

        formatted_time = local_time.strftime("%a, %d %b %Y %H:%M:%S (local_time)")

        return formatted_time