package com.google.firebase.crashlytics.internal.model;

/* renamed from: com.google.firebase.crashlytics.internal.model.b, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3926b implements com.google.firebase.encoders.c {
    public static final C3926b a = new C3926b();
    public static final com.google.firebase.encoders.b b = com.google.firebase.encoders.b.b("pid");
    public static final com.google.firebase.encoders.b c = com.google.firebase.encoders.b.b("processName");
    public static final com.google.firebase.encoders.b d = com.google.firebase.encoders.b.b("reasonCode");
    public static final com.google.firebase.encoders.b e = com.google.firebase.encoders.b.b("importance");
    public static final com.google.firebase.encoders.b f = com.google.firebase.encoders.b.b("pss");
    public static final com.google.firebase.encoders.b g = com.google.firebase.encoders.b.b("rss");
    public static final com.google.firebase.encoders.b h = com.google.firebase.encoders.b.b("timestamp");
    public static final com.google.firebase.encoders.b i = com.google.firebase.encoders.b.b("traceFile");
    public static final com.google.firebase.encoders.b j = com.google.firebase.encoders.b.b("buildIdMappingForArch");

    @Override // com.google.firebase.encoders.a
    public final void a(Object obj, Object obj2) {
        com.google.firebase.encoders.d dVar = (com.google.firebase.encoders.d) obj2;
        D d2 = (D) ((q0) obj);
        dVar.c(b, d2.a);
        dVar.g(c, d2.b);
        dVar.c(d, d2.c);
        dVar.c(e, d2.d);
        dVar.b(f, d2.e);
        dVar.b(g, d2.f);
        dVar.b(h, d2.g);
        dVar.g(i, d2.h);
        dVar.g(j, d2.i);
    }
}
