package com.google.firebase.crashlytics.internal.model;

/* renamed from: com.google.firebase.crashlytics.internal.model.g, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3936g implements com.google.firebase.encoders.c {
    public static final C3936g a = new C3936g();
    public static final com.google.firebase.encoders.b b = com.google.firebase.encoders.b.b("identifier");
    public static final com.google.firebase.encoders.b c = com.google.firebase.encoders.b.b("version");
    public static final com.google.firebase.encoders.b d = com.google.firebase.encoders.b.b("displayVersion");
    public static final com.google.firebase.encoders.b e = com.google.firebase.encoders.b.b("organization");
    public static final com.google.firebase.encoders.b f = com.google.firebase.encoders.b.b("installationUuid");
    public static final com.google.firebase.encoders.b g = com.google.firebase.encoders.b.b("developmentPlatform");
    public static final com.google.firebase.encoders.b h = com.google.firebase.encoders.b.b("developmentPlatformVersion");

    @Override // com.google.firebase.encoders.a
    public final void a(Object obj, Object obj2) {
        com.google.firebase.encoders.d dVar = (com.google.firebase.encoders.d) obj2;
        K k = (K) ((v0) obj);
        dVar.g(b, k.a);
        dVar.g(c, k.b);
        dVar.g(d, k.c);
        dVar.g(e, null);
        dVar.g(f, k.d);
        dVar.g(g, k.e);
        dVar.g(h, k.f);
    }
}
