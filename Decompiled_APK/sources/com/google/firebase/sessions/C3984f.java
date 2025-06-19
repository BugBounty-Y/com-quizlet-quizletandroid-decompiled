package com.google.firebase.sessions;

/* renamed from: com.google.firebase.sessions.f, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3984f implements com.google.firebase.encoders.c {
    public static final C3984f a = new C3984f();
    public static final com.google.firebase.encoders.b b = com.google.firebase.encoders.b.b("processName");
    public static final com.google.firebase.encoders.b c = com.google.firebase.encoders.b.b("pid");
    public static final com.google.firebase.encoders.b d = com.google.firebase.encoders.b.b("importance");
    public static final com.google.firebase.encoders.b e = com.google.firebase.encoders.b.b("defaultProcess");

    @Override // com.google.firebase.encoders.a
    public final void a(Object obj, Object obj2) {
        D d2 = (D) obj;
        com.google.firebase.encoders.d dVar = (com.google.firebase.encoders.d) obj2;
        dVar.g(b, d2.a);
        dVar.c(c, d2.b);
        dVar.c(d, d2.c);
        dVar.a(e, d2.d);
    }
}
