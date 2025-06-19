package com.google.android.gms.internal.measurement;

/* loaded from: classes2.dex */
public final class V3 implements U3 {
    public static final F1 a;

    static {
        androidx.appcompat.app.K k = new androidx.appcompat.app.K(B1.a(), true, true);
        k.Q("measurement.client.sessions.background_sessions_enabled", true);
        a = k.Q("measurement.client.sessions.enable_fix_background_engagement", false);
        k.Q("measurement.client.sessions.immediate_start_enabled_foreground", true);
        k.Q("measurement.client.sessions.enable_pause_engagement_in_background", true);
        k.Q("measurement.client.sessions.session_id_enabled", true);
        k.O(0L, "measurement.id.client.sessions.enable_fix_background_engagement");
    }
}
