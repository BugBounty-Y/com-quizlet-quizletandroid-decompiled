package com.google.firebase.sessions;

/* renamed from: com.google.firebase.sessions.g, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3985g implements com.google.firebase.encoders.c {
    public static final C3985g a = new C3985g();
    public static final com.google.firebase.encoders.b b = com.google.firebase.encoders.b.b("eventType");
    public static final com.google.firebase.encoders.b c = com.google.firebase.encoders.b.b("sessionData");
    public static final com.google.firebase.encoders.b d = com.google.firebase.encoders.b.b("applicationInfo");

    @Override // com.google.firebase.encoders.a
    public final void a(Object obj, Object obj2) {
        O o = (O) obj;
        com.google.firebase.encoders.d dVar = (com.google.firebase.encoders.d) obj2;
        o.getClass();
        dVar.g(b, EnumC3992n.SESSION_START);
        dVar.g(c, o.a);
        dVar.g(d, o.b);
    }
}
