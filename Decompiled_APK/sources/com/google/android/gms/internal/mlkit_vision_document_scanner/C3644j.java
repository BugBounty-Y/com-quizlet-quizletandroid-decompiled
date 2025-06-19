package com.google.android.gms.internal.mlkit_vision_document_scanner;

/* renamed from: com.google.android.gms.internal.mlkit_vision_document_scanner.j, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3644j implements InterfaceC3668m {
    public final int b;

    public C3644j(int i) {
        this.b = i;
    }

    @Override // java.lang.annotation.Annotation
    public final Class annotationType() {
        return InterfaceC3668m.class;
    }

    @Override // java.lang.annotation.Annotation
    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof InterfaceC3668m)) {
            return false;
        }
        C3644j c3644j = (C3644j) ((InterfaceC3668m) obj);
        if (this.b != c3644j.b) {
            return false;
        }
        Object obj2 = EnumC3660l.a;
        c3644j.getClass();
        return obj2.equals(obj2);
    }

    @Override // java.lang.annotation.Annotation
    public final int hashCode() {
        return (this.b ^ 14552422) + (EnumC3660l.a.hashCode() ^ 2041407134);
    }

    @Override // java.lang.annotation.Annotation
    public final String toString() {
        return "@com.google.firebase.encoders.proto.Protobuf(tag=" + this.b + "intEncoding=" + EnumC3660l.a + ')';
    }
}
