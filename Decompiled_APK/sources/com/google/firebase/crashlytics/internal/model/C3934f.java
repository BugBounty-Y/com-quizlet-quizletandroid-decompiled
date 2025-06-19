package com.google.firebase.crashlytics.internal.model;

/* renamed from: com.google.firebase.crashlytics.internal.model.f, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3934f implements com.google.firebase.encoders.c {
    public static final C3934f a = new C3934f();
    public static final com.google.firebase.encoders.b b = com.google.firebase.encoders.b.b("filename");
    public static final com.google.firebase.encoders.b c = com.google.firebase.encoders.b.b("contents");

    @Override // com.google.firebase.encoders.a
    public final void a(Object obj, Object obj2) {
        com.google.firebase.encoders.d dVar = (com.google.firebase.encoders.d) obj2;
        H h = (H) ((s0) obj);
        dVar.g(b, h.a);
        dVar.g(c, h.b);
    }
}
