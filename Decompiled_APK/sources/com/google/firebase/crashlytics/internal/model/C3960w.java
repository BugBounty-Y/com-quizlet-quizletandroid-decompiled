package com.google.firebase.crashlytics.internal.model;

/* renamed from: com.google.firebase.crashlytics.internal.model.w, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3960w implements com.google.firebase.encoders.c {
    public static final C3960w a = new C3960w();
    public static final com.google.firebase.encoders.b b = com.google.firebase.encoders.b.b("rolloutId");
    public static final com.google.firebase.encoders.b c = com.google.firebase.encoders.b.b("variantId");

    @Override // com.google.firebase.encoders.a
    public final void a(Object obj, Object obj2) {
        com.google.firebase.encoders.d dVar = (com.google.firebase.encoders.d) obj2;
        C3937g0 c3937g0 = (C3937g0) ((H0) obj);
        dVar.g(b, c3937g0.a);
        dVar.g(c, c3937g0.b);
    }
}
