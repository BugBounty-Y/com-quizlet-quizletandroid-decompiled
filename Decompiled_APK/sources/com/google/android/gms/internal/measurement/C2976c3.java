package com.google.android.gms.internal.measurement;

/* renamed from: com.google.android.gms.internal.measurement.c3, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2976c3 implements InterfaceC2971b3 {
    public static final F1 a;
    public static final F1 b;

    static {
        androidx.appcompat.app.K k = new androidx.appcompat.app.K(B1.a(), true, true);
        k.Q("measurement.collection.event_safelist", true);
        a = k.Q("measurement.service.store_null_safelist", true);
        b = k.Q("measurement.service.store_safelist", true);
    }
}
