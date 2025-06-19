package com.google.firebase.crashlytics.internal.model;

/* renamed from: com.google.firebase.crashlytics.internal.model.m, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3948m implements com.google.firebase.encoders.c {
    public static final C3948m a = new C3948m();
    public static final com.google.firebase.encoders.b b = com.google.firebase.encoders.b.b("threads");
    public static final com.google.firebase.encoders.b c = com.google.firebase.encoders.b.b("exception");
    public static final com.google.firebase.encoders.b d = com.google.firebase.encoders.b.b("appExitInfo");
    public static final com.google.firebase.encoders.b e = com.google.firebase.encoders.b.b("signal");
    public static final com.google.firebase.encoders.b f = com.google.firebase.encoders.b.b("binaries");

    @Override // com.google.firebase.encoders.a
    public final void a(Object obj, Object obj2) {
        com.google.firebase.encoders.d dVar = (com.google.firebase.encoders.d) obj2;
        S s = (S) ((C0) obj);
        dVar.g(b, s.a);
        dVar.g(c, s.b);
        dVar.g(d, s.c);
        dVar.g(e, s.d);
        dVar.g(f, s.e);
    }
}
