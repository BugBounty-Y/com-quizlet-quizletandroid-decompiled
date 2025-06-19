package com.google.android.gms.internal.measurement;

/* renamed from: com.google.android.gms.internal.measurement.x3, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3080x3 implements InterfaceC3075w3 {
    public static final F1 a;

    static {
        androidx.appcompat.app.K k = new androidx.appcompat.app.K(B1.a(), true, true);
        k.Q("measurement.gmscore_feature_tracking", true);
        a = k.Q("measurement.gmscore_client_telemetry", false);
    }
}
