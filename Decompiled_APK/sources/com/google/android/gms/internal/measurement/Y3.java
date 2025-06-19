package com.google.android.gms.internal.measurement;

/* loaded from: classes2.dex */
public final class Y3 implements X3 {
    public static final F1 a;
    public static final F1 b;
    public static final F1 c;
    public static final F1 d;
    public static final F1 e;
    public static final F1 f;
    public static final F1 g;
    public static final F1 h;

    static {
        androidx.appcompat.app.K k = new androidx.appcompat.app.K(B1.a(), true, true);
        a = k.Q("measurement.sgtm.client.scion_upload_action", true);
        b = k.Q("measurement.sgtm.client.upload_on_backgrounded.dev", false);
        c = k.Q("measurement.sgtm.google_signal.enable", true);
        k.Q("measurement.sgtm.no_proxy.client", true);
        d = k.Q("measurement.sgtm.no_proxy.client2", false);
        e = k.Q("measurement.sgtm.no_proxy.service", false);
        k.Q("measurement.sgtm.preview_mode_enabled", true);
        k.Q("measurement.sgtm.rollout_percentage_fix", true);
        k.Q("measurement.sgtm.service", true);
        f = k.Q("measurement.sgtm.service.batching_on_backgrounded", false);
        g = k.Q("measurement.sgtm.upload_queue", true);
        h = k.Q("measurement.sgtm.upload_on_uninstall", true);
        k.O(0L, "measurement.id.sgtm");
        k.O(0L, "measurement.id.sgtm_noproxy");
    }
}
