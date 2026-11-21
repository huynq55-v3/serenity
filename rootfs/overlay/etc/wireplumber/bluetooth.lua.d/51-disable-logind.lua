-- Serenity Linux does not run systemd-logind (/run/systemd/seats is absent).
-- Disable WirePlumber's logind seat monitor so wireplumber does not abort
-- with ENOENT before registering ALSA / Intel SOF audio devices.
bluez_monitor.properties["with-logind"] = false
bluez_midi_monitor.properties["with-logind"] = false
