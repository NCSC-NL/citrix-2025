from flow.record import RecordDescriptor


FindingRecord = RecordDescriptor(
    "ioc/hit",
    [
        ("string", "type"),
        ("string", "alert"),
        ("string", "confidence"),
        ("string", "path"),
    ],
)
