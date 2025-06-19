package com.google.firebase.crashlytics.internal.model;

/* renamed from: com.google.firebase.crashlytics.internal.model.p, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3954p implements com.google.firebase.encoders.c {
    public static final C3954p a = new C3954p();
    public static final com.google.firebase.encoders.b b = com.google.firebase.encoders.b.b("name");
    public static final com.google.firebase.encoders.b c = com.google.firebase.encoders.b.b("importance");
    public static final com.google.firebase.encoders.b d = com.google.firebase.encoders.b.b("frames");

    @Override // com.google.firebase.encoders.a
    public final void a(Object obj, Object obj2) {
        com.google.firebase.encoders.d dVar = (com.google.firebase.encoders.d) obj2;
        W w = (W) ((B0) obj);
        dVar.g(b, w.a);
        dVar.c(c, w.b);
        dVar.g(d, w.c);
    }
}
