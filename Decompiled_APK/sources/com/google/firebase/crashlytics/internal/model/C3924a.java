package com.google.firebase.crashlytics.internal.model;

/* renamed from: com.google.firebase.crashlytics.internal.model.a, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3924a implements com.google.firebase.encoders.c {
    public static final C3924a a = new C3924a();
    public static final com.google.firebase.encoders.b b = com.google.firebase.encoders.b.b("arch");
    public static final com.google.firebase.encoders.b c = com.google.firebase.encoders.b.b("libraryName");
    public static final com.google.firebase.encoders.b d = com.google.firebase.encoders.b.b("buildId");

    @Override // com.google.firebase.encoders.a
    public final void a(Object obj, Object obj2) {
        com.google.firebase.encoders.d dVar = (com.google.firebase.encoders.d) obj2;
        E e = (E) ((p0) obj);
        dVar.g(b, e.a);
        dVar.g(c, e.b);
        dVar.g(d, e.c);
    }
}
