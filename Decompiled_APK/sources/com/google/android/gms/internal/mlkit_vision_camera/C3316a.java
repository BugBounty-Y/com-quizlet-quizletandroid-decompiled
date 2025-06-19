package com.google.android.gms.internal.mlkit_vision_camera;

/* renamed from: com.google.android.gms.internal.mlkit_vision_camera.a, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3316a implements B1 {
    public final int b;

    public C3316a(int i) {
        this.b = i;
    }

    @Override // java.lang.annotation.Annotation
    public final Class annotationType() {
        return B1.class;
    }

    @Override // java.lang.annotation.Annotation
    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof B1)) {
            return false;
        }
        C3316a c3316a = (C3316a) ((B1) obj);
        if (this.b != c3316a.b) {
            return false;
        }
        Object obj2 = EnumC3330d1.a;
        c3316a.getClass();
        return obj2.equals(obj2);
    }

    @Override // java.lang.annotation.Annotation
    public final int hashCode() {
        return (this.b ^ 14552422) + (EnumC3330d1.a.hashCode() ^ 2041407134);
    }

    @Override // java.lang.annotation.Annotation
    public final String toString() {
        return "@com.google.firebase.encoders.proto.Protobuf(tag=" + this.b + "intEncoding=" + EnumC3330d1.a + ')';
    }
}
