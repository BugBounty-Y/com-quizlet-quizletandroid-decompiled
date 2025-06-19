package com.google.android.gms.internal.measurement;

/* renamed from: com.google.android.gms.internal.measurement.f3, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2991f3 implements InterfaceC2986e3 {
    public static final F1 a;
    public static final F1 b;
    public static final F1 c;

    static {
        androidx.appcompat.app.K k = new androidx.appcompat.app.K(B1.a(), true, true);
        k.Q("measurement.service.audience.fix_skip_audience_with_failed_filters", true);
        a = k.Q("measurement.audience.refresh_event_count_filters_timestamp", false);
        b = k.Q("measurement.audience.use_bundle_end_timestamp_for_non_sequence_property_filters", false);
        c = k.Q("measurement.audience.use_bundle_timestamp_for_event_count_filters", false);
    }
}
