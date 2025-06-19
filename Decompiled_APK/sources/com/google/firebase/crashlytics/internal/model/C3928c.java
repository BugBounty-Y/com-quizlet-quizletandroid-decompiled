package com.google.firebase.crashlytics.internal.model;

/* renamed from: com.google.firebase.crashlytics.internal.model.c, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3928c implements com.google.firebase.encoders.c {
    public static final C3928c a = new C3928c();
    public static final com.google.firebase.encoders.b b = com.google.firebase.encoders.b.b("key");
    public static final com.google.firebase.encoders.b c = com.google.firebase.encoders.b.b("value");

    @Override // com.google.firebase.encoders.a
    public final void a(Object obj, Object obj2) {
        com.google.firebase.encoders.d dVar = (com.google.firebase.encoders.d) obj2;
        F f = (F) ((r0) obj);
        dVar.g(b, f.a);
        dVar.g(c, f.b);
    }
}
