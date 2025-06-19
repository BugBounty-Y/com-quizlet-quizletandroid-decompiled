package com.google.android.gms.internal.measurement;

/* loaded from: classes2.dex */
public final class W2 implements V2 {
    public static final F1 a;
    public static final F1 b;
    public static final F1 c;

    static {
        androidx.appcompat.app.K k = new androidx.appcompat.app.K(B1.a(), true, true);
        k.Q("measurement.set_default_event_parameters_with_backfill.client.dev", false);
        k.Q("measurement.set_default_event_parameters_with_backfill.service", true);
        k.O(0L, "measurement.id.set_default_event_parameters.fix_service_request_ordering");
        a = k.Q("measurement.set_default_event_parameters.fix_app_update_logging", true);
        b = k.Q("measurement.set_default_event_parameters.fix_deferred_analytics_collection", true);
        c = k.Q("measurement.set_default_event_parameters.fix_service_request_ordering", false);
        k.Q("measurement.set_default_event_parameters.fix_subsequent_launches", true);
    }
}
