package com.google.android.gms.internal.measurement;

/* loaded from: classes2.dex */
public final class Z2 implements Y2 {
    public static final F1 a;
    public static final F1 b;

    static {
        androidx.appcompat.app.K k = new androidx.appcompat.app.K(B1.a(), true, true);
        a = k.Q("measurement.set_default_event_parameters_propagate_clear.client.dev", false);
        b = k.Q("measurement.set_default_event_parameters_propagate_clear.service", false);
        k.O(0L, "measurement.id.set_default_event_parameters_propagate_clear.experiment_id");
    }
}
