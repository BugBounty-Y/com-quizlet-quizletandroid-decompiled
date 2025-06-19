package com.google.firebase.crashlytics.internal.model;

/* renamed from: com.google.firebase.crashlytics.internal.model.o, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3952o implements com.google.firebase.encoders.c {
    public static final C3952o a = new C3952o();
    public static final com.google.firebase.encoders.b b = com.google.firebase.encoders.b.b("name");
    public static final com.google.firebase.encoders.b c = com.google.firebase.encoders.b.b("code");
    public static final com.google.firebase.encoders.b d = com.google.firebase.encoders.b.b("address");

    @Override // com.google.firebase.encoders.a
    public final void a(Object obj, Object obj2) {
        com.google.firebase.encoders.d dVar = (com.google.firebase.encoders.d) obj2;
        V v = (V) ((z0) obj);
        dVar.g(b, v.a);
        dVar.g(c, v.b);
        dVar.b(d, v.c);
    }
}
