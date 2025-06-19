package com.google.android.datatransport.runtime;

/* loaded from: classes2.dex */
public final class f implements com.google.firebase.encoders.c {
    public static final f a = new f();
    public static final com.google.firebase.encoders.b b = new com.google.firebase.encoders.b("currentCacheSizeBytes", assistantMode.refactored.a.o(assistantMode.refactored.a.n(com.google.firebase.encoders.proto.d.class, new com.google.firebase.encoders.proto.a(1))));
    public static final com.google.firebase.encoders.b c = new com.google.firebase.encoders.b("maxCacheSizeBytes", assistantMode.refactored.a.o(assistantMode.refactored.a.n(com.google.firebase.encoders.proto.d.class, new com.google.firebase.encoders.proto.a(2))));

    @Override // com.google.firebase.encoders.a
    public final void a(Object obj, Object obj2) {
        com.google.android.datatransport.runtime.firebase.transport.f fVar = (com.google.android.datatransport.runtime.firebase.transport.f) obj;
        com.google.firebase.encoders.d dVar = (com.google.firebase.encoders.d) obj2;
        dVar.b(b, fVar.a);
        dVar.b(c, fVar.b);
    }
}
