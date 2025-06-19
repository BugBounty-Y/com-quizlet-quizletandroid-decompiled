package com.google.firebase.crashlytics.internal.model;

import com.amazon.device.ads.DtbDeviceData;

/* renamed from: com.google.firebase.crashlytics.internal.model.s, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3956s implements com.google.firebase.encoders.c {
    public static final C3956s a = new C3956s();
    public static final com.google.firebase.encoders.b b = com.google.firebase.encoders.b.b("batteryLevel");
    public static final com.google.firebase.encoders.b c = com.google.firebase.encoders.b.b("batteryVelocity");
    public static final com.google.firebase.encoders.b d = com.google.firebase.encoders.b.b("proximityOn");
    public static final com.google.firebase.encoders.b e = com.google.firebase.encoders.b.b(DtbDeviceData.DEVICE_DATA_ORIENTATION_KEY);
    public static final com.google.firebase.encoders.b f = com.google.firebase.encoders.b.b("ramUsed");
    public static final com.google.firebase.encoders.b g = com.google.firebase.encoders.b.b("diskUsed");

    @Override // com.google.firebase.encoders.a
    public final void a(Object obj, Object obj2) {
        com.google.firebase.encoders.d dVar = (com.google.firebase.encoders.d) obj2;
        C3929c0 c3929c0 = (C3929c0) ((F0) obj);
        dVar.g(b, c3929c0.a);
        dVar.c(c, c3929c0.b);
        dVar.a(d, c3929c0.c);
        dVar.c(e, c3929c0.d);
        dVar.b(f, c3929c0.e);
        dVar.b(g, c3929c0.f);
    }
}
