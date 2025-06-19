package com.google.android.gms.internal.measurement;

/* loaded from: classes2.dex */
public final class S3 implements R3 {
    public static final F1 a;

    static {
        androidx.appcompat.app.K k = new androidx.appcompat.app.K(B1.a(), true, true);
        k.Q("measurement.collection.enable_session_stitching_token.client.dev", true);
        a = k.Q("measurement.session_stitching_token_enabled", false);
        k.Q("measurement.link_sst_to_sid", true);
    }
}
