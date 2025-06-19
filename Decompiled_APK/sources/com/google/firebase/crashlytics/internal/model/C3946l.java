package com.google.firebase.crashlytics.internal.model;

/* renamed from: com.google.firebase.crashlytics.internal.model.l, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3946l implements com.google.firebase.encoders.c {
    public static final C3946l a = new C3946l();
    public static final com.google.firebase.encoders.b b = com.google.firebase.encoders.b.b("baseAddress");
    public static final com.google.firebase.encoders.b c = com.google.firebase.encoders.b.b("size");
    public static final com.google.firebase.encoders.b d = com.google.firebase.encoders.b.b("name");
    public static final com.google.firebase.encoders.b e = com.google.firebase.encoders.b.b("uuid");

    @Override // com.google.firebase.encoders.a
    public final void a(Object obj, Object obj2) {
        com.google.firebase.encoders.d dVar = (com.google.firebase.encoders.d) obj2;
        T t = (T) ((x0) obj);
        dVar.b(b, t.a);
        dVar.b(c, t.b);
        dVar.g(d, t.c);
        String str = t.d;
        dVar.g(e, str != null ? str.getBytes(O0.a) : null);
    }
}
