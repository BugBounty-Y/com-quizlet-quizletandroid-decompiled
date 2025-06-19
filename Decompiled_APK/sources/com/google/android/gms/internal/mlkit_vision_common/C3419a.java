package com.google.android.gms.internal.mlkit_vision_common;

/* renamed from: com.google.android.gms.internal.mlkit_vision_common.a, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3419a implements InterfaceC3437d {
    public final int b;

    public C3419a(int i) {
        this.b = i;
    }

    @Override // java.lang.annotation.Annotation
    public final Class annotationType() {
        return InterfaceC3437d.class;
    }

    @Override // java.lang.annotation.Annotation
    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof InterfaceC3437d)) {
            return false;
        }
        C3419a c3419a = (C3419a) ((InterfaceC3437d) obj);
        if (this.b != c3419a.b) {
            return false;
        }
        Object obj2 = EnumC3431c.a;
        c3419a.getClass();
        return obj2.equals(obj2);
    }

    @Override // java.lang.annotation.Annotation
    public final int hashCode() {
        return (this.b ^ 14552422) + (EnumC3431c.a.hashCode() ^ 2041407134);
    }

    @Override // java.lang.annotation.Annotation
    public final String toString() {
        return "@com.google.firebase.encoders.proto.Protobuf(tag=" + this.b + "intEncoding=" + EnumC3431c.a + ')';
    }
}
