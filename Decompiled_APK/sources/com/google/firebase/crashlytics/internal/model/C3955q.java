package com.google.firebase.crashlytics.internal.model;

/* renamed from: com.google.firebase.crashlytics.internal.model.q, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3955q implements com.google.firebase.encoders.c {
    public static final C3955q a = new C3955q();
    public static final com.google.firebase.encoders.b b = com.google.firebase.encoders.b.b("pc");
    public static final com.google.firebase.encoders.b c = com.google.firebase.encoders.b.b("symbol");
    public static final com.google.firebase.encoders.b d = com.google.firebase.encoders.b.b("file");
    public static final com.google.firebase.encoders.b e = com.google.firebase.encoders.b.b("offset");
    public static final com.google.firebase.encoders.b f = com.google.firebase.encoders.b.b("importance");

    @Override // com.google.firebase.encoders.a
    public final void a(Object obj, Object obj2) {
        com.google.firebase.encoders.d dVar = (com.google.firebase.encoders.d) obj2;
        Y y = (Y) ((A0) obj);
        dVar.b(b, y.a);
        dVar.g(c, y.b);
        dVar.g(d, y.c);
        dVar.b(e, y.d);
        dVar.c(f, y.e);
    }
}
