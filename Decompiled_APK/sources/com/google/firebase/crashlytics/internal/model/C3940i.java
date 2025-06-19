package com.google.firebase.crashlytics.internal.model;

import com.amazon.device.ads.DtbDeviceData;

/* renamed from: com.google.firebase.crashlytics.internal.model.i, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3940i implements com.google.firebase.encoders.c {
    public static final C3940i a = new C3940i();
    public static final com.google.firebase.encoders.b b = com.google.firebase.encoders.b.b("arch");
    public static final com.google.firebase.encoders.b c = com.google.firebase.encoders.b.b(DtbDeviceData.DEVICE_DATA_MODEL_KEY);
    public static final com.google.firebase.encoders.b d = com.google.firebase.encoders.b.b("cores");
    public static final com.google.firebase.encoders.b e = com.google.firebase.encoders.b.b("ram");
    public static final com.google.firebase.encoders.b f = com.google.firebase.encoders.b.b("diskSpace");
    public static final com.google.firebase.encoders.b g = com.google.firebase.encoders.b.b("simulator");
    public static final com.google.firebase.encoders.b h = com.google.firebase.encoders.b.b("state");
    public static final com.google.firebase.encoders.b i = com.google.firebase.encoders.b.b("manufacturer");
    public static final com.google.firebase.encoders.b j = com.google.firebase.encoders.b.b("modelClass");

    @Override // com.google.firebase.encoders.a
    public final void a(Object obj, Object obj2) {
        com.google.firebase.encoders.d dVar = (com.google.firebase.encoders.d) obj2;
        N n = (N) ((w0) obj);
        dVar.c(b, n.a);
        dVar.g(c, n.b);
        dVar.c(d, n.c);
        dVar.b(e, n.d);
        dVar.b(f, n.e);
        dVar.a(g, n.f);
        dVar.c(h, n.g);
        dVar.g(i, n.h);
        dVar.g(j, n.i);
    }
}
