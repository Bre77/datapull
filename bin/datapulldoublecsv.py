import os
import sys
import time
import requests
import csv

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
from splunklib.modularinput import *


class Input(Script):
    MASK = "<encrypted>"
    APP = "datapull"

    def get_scheme(self):
        scheme = Scheme("Data Pull (Double)")
        scheme.description = "Index data from a Splunk Search Head. Put the target index name as the input name"
        scheme.use_external_validation = False
        scheme.streaming_mode_xml = True
        scheme.use_single_instance = False

        scheme.add_argument(
            Argument(
                name="searchhead",
                title="Search Head",
                data_type=Argument.data_type_string,
                required_on_create=True,
                required_on_edit=False,
            )
        )
        scheme.add_argument(
            Argument(
                name="port",
                title="Splunkd Port",
                data_type=Argument.data_type_string,
                required_on_create=True,
                required_on_edit=False,
            )
        )
        scheme.add_argument(
            Argument(
                name="authtoken",
                title="Auth Token",
                data_type=Argument.data_type_string,
                required_on_create=True,
                required_on_edit=False,
            )
        )
        scheme.add_argument(
            Argument(
                name="earliest",
                title="Earliest",
                data_type=Argument.data_type_string,
                required_on_create=True,
                required_on_edit=False,
            )
        )
        scheme.add_argument(
            Argument(
                name="latest",
                title="Latest",
                data_type=Argument.data_type_string,
                required_on_create=True,
                required_on_edit=False,
            )
        )

        return scheme

    def stream_events(self, inputs, ew):
        global killer
        self.service.namespace["app"] = self.APP
        # Get Variables
        input_name, input_items = inputs.inputs.popitem()
        kind, name = input_name.split("://")
        checkpointfile = os.path.join(
            self._input_definition.metadata["checkpoint_dir"], name
        )
        input = self.service.inputs.__getitem__((name, kind))
        # Set start to earliest days ago
        start = int(time.time()) - (int(input_items["earliest"]) * 86400)
        end = int(time.time()) - (int(input_items["latest"]) * 86400)
        url = f"https://{input_items['searchhead']}:{input_items.get('port','8089')}/services/search/v2/jobs/export"
        MOD = 1000

        ew.log(
            EventWriter.INFO,
            f"status=startup name={name} url={url}",
        )

        # Password Encryption
        auth = {}
        updates = {}

        for item in ["authtoken"]:
            stored_password = [
                x
                for x in self.service.storage_passwords
                if x.username == item and x.realm == name
            ]
            if input_items[item] == self.MASK:
                if len(stored_password) != 1:
                    ew.log(
                        EventWriter.ERROR,
                        f"Encrypted {item} was not found for {input_name}, reconfigure its value.",
                    )
                    return
                auth[item] = stored_password[0].content.clear_password
            else:
                if stored_password:
                    ew.log(EventWriter.DEBUG, "Removing Current password")
                    self.service.storage_passwords.delete(username=item, realm=name)
                ew.log(EventWriter.DEBUG, "Storing password and updating Input")
                self.service.storage_passwords.create(input_items[item], item, name)
                updates[item] = self.MASK
                auth[item] = input_items[item]
        if updates:
            input.update(**updates)

        # Checkpoint
        try:
            earliest = max(int(open(checkpointfile, "r").read()), start)
        except:
            earliest = start

        prev = None
        with requests.Session() as s:
            s.headers.update({"Authorization": f"Splunk {auth['authtoken']}"})
            # Do the logic
            while True:
                if earliest < end:
                    latest = min(earliest + 86400, end)
                    ew.log(
                        EventWriter.INFO,
                        f"status=search name={name} earliest={earliest} latest={latest} start={start} end={end}",
                    )
                    next = s.post(
                        url,
                        stream=True,
                        data={
                            "search": f"search index={name}",
                            "earliest_time": earliest,
                            "latest_time": latest,
                            "enable_lookups": False,
                            "output_mode": "csv",
                            "exec_mode": "oneshot",
                            "time_format": "%s",
                            "adhoc_search_level": "fast",
                            "f": [
                                "_time",
                                "host",
                                "source",
                                "sourcetype",
                                "_raw",
                            ],
                        },
                    )
                if prev:
                    if prev.status_code != requests.codes.ok:
                        ew.log(
                            EventWriter.ERROR,
                            f"status=error name={name} response={prev.text}",
                        )
                        time.sleep(1)
                        input.disable()
                        break
                    count = 0
                    reader = csv.reader(
                        prev.iter_lines(decode_unicode=True),
                        delimiter=",",
                        quotechar='"',
                    )
                    for row in reader:
                        ew.write_event(
                            Event(
                                index=input_name,
                                time=row["_time"],
                                host=row["host"],
                                source=row["source"],
                                sourcetype=row["sourcetype"],
                                data=row["_raw"],
                            )
                        )
                        count += 1
                        if count % MOD == 0:
                            ew.log(
                                EventWriter.INFO,
                                f"status=progress progress={MOD} name={name} current={data['result']['_time']}",
                            )
                    # Save Progress (prev ends where next started)
                    open(checkpointfile, "w").write(str(earliest))

                    ew.log(
                        EventWriter.INFO,
                        f"status=done total={count} progress={count % MOD} name={name}",
                    )

                if not next:
                    break

                earliest = latest
                prev = next
                next = None


if __name__ == "__main__":
    exitcode = Input().run(sys.argv)
    sys.exit(exitcode)
