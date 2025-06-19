package com.google.firebase.sessions;

/* renamed from: com.google.firebase.sessions.e, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3983e implements com.google.firebase.encoders.c {
    public static final C3983e a = new C3983e();
    public static final com.google.firebase.encoders.b b = com.google.firebase.encoders.b.b("performance");
    public static final com.google.firebase.encoders.b c = com.google.firebase.encoders.b.b("crashlytics");
    public static final com.google.firebase.encoders.b d = com.google.firebase.encoders.b.b("sessionSamplingRate");

    @Override // com.google.firebase.encoders.a
    public final void a(Object obj, Object obj2) {
        C3989k c3989k = (C3989k) obj;
        com.google.firebase.encoders.d dVar = (com.google.firebase.encoders.d) obj2;
        dVar.g(b, c3989k.a);
        dVar.g(c, c3989k.b);
        dVar.d(d, c3989k.c);
    }
}
