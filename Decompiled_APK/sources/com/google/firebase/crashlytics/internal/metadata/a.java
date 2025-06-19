package com.google.firebase.crashlytics.internal.metadata;

/* loaded from: classes2.dex */
public final class a implements com.google.firebase.encoders.c {
    public static final a a = new a();
    public static final com.google.firebase.encoders.b b = com.google.firebase.encoders.b.b("rolloutId");
    public static final com.google.firebase.encoders.b c = com.google.firebase.encoders.b.b("parameterKey");
    public static final com.google.firebase.encoders.b d = com.google.firebase.encoders.b.b("parameterValue");
    public static final com.google.firebase.encoders.b e = com.google.firebase.encoders.b.b("variantId");
    public static final com.google.firebase.encoders.b f = com.google.firebase.encoders.b.b("templateVersion");

    @Override // com.google.firebase.encoders.a
    public final void a(Object obj, Object obj2) {
        com.google.firebase.encoders.d dVar = (com.google.firebase.encoders.d) obj2;
        b bVar = (b) ((o) obj);
        dVar.g(b, bVar.b);
        dVar.g(c, bVar.c);
        dVar.g(d, bVar.d);
        dVar.g(e, bVar.e);
        dVar.b(f, bVar.f);
    }
}
