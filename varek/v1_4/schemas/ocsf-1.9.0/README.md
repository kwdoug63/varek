# OCSF 1.9.0, as the VAREK OCSF export uses it

`schema.json` is part of the Open Cybersecurity Schema Framework (OCSF)
schema, version 1.9.0, from the OCSF project's repository
(https://github.com/ocsf/ocsf-schema, tag `1.9.0`, commit `856d462`),
compiled by the OCSF project's own compiler (`ocsf-lib` 0.10.4,
`python -m ocsf.compile`) with the profiles `security_control`,
`ai_operation` and `host` and no extensions, and cut down to the event
classes the export writes (File System Activity, Process Activity, Network
Activity, HTTP Activity, DNS Activity, Application Lifecycle, API Activity)
and the objects and types they reach. Nothing in it is changed.
`tools/ocsf_vendor.py` makes it again from those two sources.

The OCSF schema is licensed under the Apache License 2.0 (`LICENSE`, and the
project's `NOTICE`, both copied here unchanged). VAREK and Sober Agentic
Infrastructure, Inc. are not affiliated with, endorsed by, or certified by
the OCSF project. The OCSF name is used only to describe interoperability
with the openly published schema.

`tests/ocsf_validate.py` checks events against this file with no network
and no OCSF software.
