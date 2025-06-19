package com.google.firebase.crashlytics.internal.model;

/* renamed from: com.google.firebase.crashlytics.internal.model.k, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3944k implements com.google.firebase.encoders.c {
    public static final C3944k a = new C3944k();
    public static final com.google.firebase.encoders.b b = com.google.firebase.encoders.b.b("execution");
    public static final com.google.firebase.encoders.b c = com.google.firebase.encoders.b.b("customAttributes");
    public static final com.google.firebase.encoders.b d = com.google.firebase.encoders.b.b("internalKeys");
    public static final com.google.firebase.encoders.b e = com.google.firebase.encoders.b.b("background");
    public static final com.google.firebase.encoders.b f = com.google.firebase.encoders.b.b("currentProcessDetails");
    public static final com.google.firebase.encoders.b g = com.google.firebase.encoders.b.b("appProcessDetails");
    public static final com.google.firebase.encoders.b h = com.google.firebase.encoders.b.b("uiOrientation");

    @Override // com.google.firebase.encoders.a
    public final void a(Object obj, Object obj2) {
        com.google.firebase.encoders.d dVar = (com.google.firebase.encoders.d) obj2;
        Q q = (Q) ((E0) obj);
        dVar.g(b, q.a);
        dVar.g(c, q.b);
        dVar.g(d, q.c);
        dVar.g(e, q.d);
        dVar.g(f, q.e);
        dVar.g(g, q.f);
        dVar.c(h, q.g);
    }
}
