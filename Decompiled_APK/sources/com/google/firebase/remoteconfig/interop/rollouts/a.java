package com.google.firebase.remoteconfig.interop.rollouts;

/* loaded from: classes2.dex */
public final class a implements com.google.firebase.encoders.c {
    public static final a a = new a();
    public static final com.google.firebase.encoders.b b = com.google.firebase.encoders.b.b("rolloutId");
    public static final com.google.firebase.encoders.b c = com.google.firebase.encoders.b.b("variantId");
    public static final com.google.firebase.encoders.b d = com.google.firebase.encoders.b.b("parameterKey");
    public static final com.google.firebase.encoders.b e = com.google.firebase.encoders.b.b("parameterValue");
    public static final com.google.firebase.encoders.b f = com.google.firebase.encoders.b.b("templateVersion");

    @Override // com.google.firebase.encoders.a
    public final void a(Object obj, Object obj2) {
        com.google.firebase.encoders.d dVar = (com.google.firebase.encoders.d) obj2;
        c cVar = (c) ((e) obj);
        dVar.g(b, cVar.b);
        dVar.g(c, cVar.c);
        dVar.g(d, cVar.d);
        dVar.g(e, cVar.e);
        dVar.b(f, cVar.f);
    }
}
