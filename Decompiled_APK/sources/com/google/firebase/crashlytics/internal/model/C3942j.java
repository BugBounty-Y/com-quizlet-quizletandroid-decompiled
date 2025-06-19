package com.google.firebase.crashlytics.internal.model;

/* renamed from: com.google.firebase.crashlytics.internal.model.j, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3942j implements com.google.firebase.encoders.c {
    public static final C3942j a = new C3942j();
    public static final com.google.firebase.encoders.b b = com.google.firebase.encoders.b.b("generator");
    public static final com.google.firebase.encoders.b c = com.google.firebase.encoders.b.b("identifier");
    public static final com.google.firebase.encoders.b d = com.google.firebase.encoders.b.b("appQualitySessionId");
    public static final com.google.firebase.encoders.b e = com.google.firebase.encoders.b.b("startedAt");
    public static final com.google.firebase.encoders.b f = com.google.firebase.encoders.b.b("endedAt");
    public static final com.google.firebase.encoders.b g = com.google.firebase.encoders.b.b("crashed");
    public static final com.google.firebase.encoders.b h = com.google.firebase.encoders.b.b("app");
    public static final com.google.firebase.encoders.b i = com.google.firebase.encoders.b.b("user");
    public static final com.google.firebase.encoders.b j = com.google.firebase.encoders.b.b("os");
    public static final com.google.firebase.encoders.b k = com.google.firebase.encoders.b.b("device");
    public static final com.google.firebase.encoders.b l = com.google.firebase.encoders.b.b("events");
    public static final com.google.firebase.encoders.b m = com.google.firebase.encoders.b.b("generatorType");

    @Override // com.google.firebase.encoders.a
    public final void a(Object obj, Object obj2) {
        com.google.firebase.encoders.d dVar = (com.google.firebase.encoders.d) obj2;
        J j2 = (J) ((N0) obj);
        dVar.g(b, j2.a);
        dVar.g(c, j2.b.getBytes(O0.a));
        dVar.g(d, j2.c);
        dVar.b(e, j2.d);
        dVar.g(f, j2.e);
        dVar.a(g, j2.f);
        dVar.g(h, j2.g);
        dVar.g(i, j2.h);
        dVar.g(j, j2.i);
        dVar.g(k, j2.j);
        dVar.g(l, j2.k);
        dVar.c(m, j2.l);
    }
}
