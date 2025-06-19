package com.google.firebase.crashlytics.internal.model;

/* renamed from: com.google.firebase.crashlytics.internal.model.d, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3930d implements com.google.firebase.encoders.c {
    public static final C3930d a = new C3930d();
    public static final com.google.firebase.encoders.b b = com.google.firebase.encoders.b.b("sdkVersion");
    public static final com.google.firebase.encoders.b c = com.google.firebase.encoders.b.b("gmpAppId");
    public static final com.google.firebase.encoders.b d = com.google.firebase.encoders.b.b("platform");
    public static final com.google.firebase.encoders.b e = com.google.firebase.encoders.b.b("installationUuid");
    public static final com.google.firebase.encoders.b f = com.google.firebase.encoders.b.b("firebaseInstallationId");
    public static final com.google.firebase.encoders.b g = com.google.firebase.encoders.b.b("firebaseAuthenticationToken");
    public static final com.google.firebase.encoders.b h = com.google.firebase.encoders.b.b("appQualitySessionId");
    public static final com.google.firebase.encoders.b i = com.google.firebase.encoders.b.b("buildVersion");
    public static final com.google.firebase.encoders.b j = com.google.firebase.encoders.b.b("displayVersion");
    public static final com.google.firebase.encoders.b k = com.google.firebase.encoders.b.b("session");
    public static final com.google.firebase.encoders.b l = com.google.firebase.encoders.b.b("ndkPayload");
    public static final com.google.firebase.encoders.b m = com.google.firebase.encoders.b.b("appExitInfo");

    @Override // com.google.firebase.encoders.a
    public final void a(Object obj, Object obj2) {
        com.google.firebase.encoders.d dVar = (com.google.firebase.encoders.d) obj2;
        B b2 = (B) ((O0) obj);
        dVar.g(b, b2.b);
        dVar.g(c, b2.c);
        dVar.c(d, b2.d);
        dVar.g(e, b2.e);
        dVar.g(f, b2.f);
        dVar.g(g, b2.g);
        dVar.g(h, b2.h);
        dVar.g(i, b2.i);
        dVar.g(j, b2.j);
        dVar.g(k, b2.k);
        dVar.g(l, b2.l);
        dVar.g(m, b2.m);
    }
}
