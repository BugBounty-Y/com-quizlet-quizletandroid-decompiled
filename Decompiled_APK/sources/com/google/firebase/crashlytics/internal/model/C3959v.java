package com.google.firebase.crashlytics.internal.model;

/* renamed from: com.google.firebase.crashlytics.internal.model.v, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3959v implements com.google.firebase.encoders.c {
    public static final C3959v a = new C3959v();
    public static final com.google.firebase.encoders.b b = com.google.firebase.encoders.b.b("rolloutVariant");
    public static final com.google.firebase.encoders.b c = com.google.firebase.encoders.b.b("parameterKey");
    public static final com.google.firebase.encoders.b d = com.google.firebase.encoders.b.b("parameterValue");
    public static final com.google.firebase.encoders.b e = com.google.firebase.encoders.b.b("templateVersion");

    @Override // com.google.firebase.encoders.a
    public final void a(Object obj, Object obj2) {
        com.google.firebase.encoders.d dVar = (com.google.firebase.encoders.d) obj2;
        C3935f0 c3935f0 = (C3935f0) ((I0) obj);
        dVar.g(b, c3935f0.a);
        dVar.g(c, c3935f0.b);
        dVar.g(d, c3935f0.c);
        dVar.b(e, c3935f0.d);
    }
}
