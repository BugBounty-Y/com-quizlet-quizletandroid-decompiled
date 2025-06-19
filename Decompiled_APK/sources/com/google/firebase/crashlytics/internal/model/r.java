package com.google.firebase.crashlytics.internal.model;

/* loaded from: classes2.dex */
public final class r implements com.google.firebase.encoders.c {
    public static final r a = new r();
    public static final com.google.firebase.encoders.b b = com.google.firebase.encoders.b.b("processName");
    public static final com.google.firebase.encoders.b c = com.google.firebase.encoders.b.b("pid");
    public static final com.google.firebase.encoders.b d = com.google.firebase.encoders.b.b("importance");
    public static final com.google.firebase.encoders.b e = com.google.firebase.encoders.b.b("defaultProcess");

    @Override // com.google.firebase.encoders.a
    public final void a(Object obj, Object obj2) {
        com.google.firebase.encoders.d dVar = (com.google.firebase.encoders.d) obj2;
        C3925a0 c3925a0 = (C3925a0) ((D0) obj);
        dVar.g(b, c3925a0.a);
        dVar.c(c, c3925a0.b);
        dVar.c(d, c3925a0.c);
        dVar.a(e, c3925a0.d);
    }
}
