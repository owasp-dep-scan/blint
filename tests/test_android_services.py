from blint.cyclonedx.spec import Component, Property
from blint.lib.android_services import detect_services


def _dex(classes):
    return Component(
        type="file",
        name="classes.dex",
        properties=[Property(name="internal:classes", value="~~".join(classes))],
    )


def test_detect_services_and_trackers():
    comp = _dex(
        [
            "com.stripe.android.Stripe",
            "io.sentry.Sentry",
            "com.datadog.android.Datadog",
            "java.lang.String",
        ]
    )
    services = {s.name: s for s in detect_services([comp])}
    assert "Stripe" in services
    assert services["Stripe"].group == "payment"
    assert services["Stripe"].bom_ref.root == "service:Stripe"
    assert services["Stripe"].data[0].flow.value == "unknown"
    # Sentry is sourced from the tracker dictionary.
    assert "Sentry" in services
    kinds = {p.name: p.value for p in services["Sentry"].properties}
    assert kinds["internal:serviceKind"] == "tracker"
    assert kinds["internal:detection"] == "static"


def test_detect_services_none_without_classes():
    assert detect_services([]) == []
    assert detect_services([Component(type="file", name="empty.dex")]) == []
