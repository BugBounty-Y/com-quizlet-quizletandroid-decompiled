package com.google.android.datatransport.runtime;

/* loaded from: classes2.dex */
public final class a implements com.google.firebase.encoders.c {
    public static final a a = new a();
    public static final com.google.firebase.encoders.b b = new com.google.firebase.encoders.b("window", assistantMode.refactored.a.o(assistantMode.refactored.a.n(com.google.firebase.encoders.proto.d.class, new com.google.firebase.encoders.proto.a(1))));
    public static final com.google.firebase.encoders.b c = new com.google.firebase.encoders.b("logSourceMetrics", assistantMode.refactored.a.o(assistantMode.refactored.a.n(com.google.firebase.encoders.proto.d.class, new com.google.firebase.encoders.proto.a(2))));
    public static final com.google.firebase.encoders.b d = new com.google.firebase.encoders.b("globalMetrics", assistantMode.refactored.a.o(assistantMode.refactored.a.n(com.google.firebase.encoders.proto.d.class, new com.google.firebase.encoders.proto.a(3))));
    public static final com.google.firebase.encoders.b e = new com.google.firebase.encoders.b("appNamespace", assistantMode.refactored.a.o(assistantMode.refactored.a.n(com.google.firebase.encoders.proto.d.class, new com.google.firebase.encoders.proto.a(4))));

    @Override // com.google.firebase.encoders.a
    public final void a(Object obj, Object obj2) {
        com.google.android.datatransport.runtime.firebase.transport.a aVar = (com.google.android.datatransport.runtime.firebase.transport.a) obj;
        com.google.firebase.encoders.d dVar = (com.google.firebase.encoders.d) obj2;
        dVar.g(b, aVar.a);
        dVar.g(c, aVar.b);
        dVar.g(d, aVar.c);
        dVar.g(e, aVar.d);
    }
}
