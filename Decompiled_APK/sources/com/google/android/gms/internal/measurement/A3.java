package com.google.android.gms.internal.measurement;

/* loaded from: classes2.dex */
public final class A3 implements InterfaceC3090z3 {
    public static final F1 a;

    static {
        androidx.appcompat.app.K k = new androidx.appcompat.app.K(B1.a(), true, true);
        k.Q("measurement.sdk.collection.enable_extend_user_property_size", true);
        a = k.Q("measurement.sdk.collection.last_deep_link_referrer_campaign2", false);
        k.O(0L, "measurement.id.sdk.collection.last_deep_link_referrer2");
    }
}
