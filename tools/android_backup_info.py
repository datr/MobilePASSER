"""Compatibility launcher for read-only Android backup inspection."""

from mobilepasser.android_backup import inspect_backup, main, read_properties, verify_android_id


if __name__ == "__main__":
    raise SystemExit(main())
