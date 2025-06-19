package com.google.android.gms.internal.fido;

import java.io.Serializable;

/* loaded from: classes2.dex */
public final class A extends AbstractC2958w implements Serializable {
    public final AbstractC2958w a;

    public A(AbstractC2958w abstractC2958w) {
        this.a = abstractC2958w;
    }

    @Override // com.google.android.gms.internal.fido.AbstractC2958w
    public final AbstractC2958w a() {
        return this.a;
    }

    @Override // java.util.Comparator
    public final int compare(Object obj, Object obj2) {
        return this.a.compare(obj2, obj);
    }

    @Override // java.util.Comparator
    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof A) {
            return this.a.equals(((A) obj).a);
        }
        return false;
    }

    public final int hashCode() {
        return -this.a.hashCode();
    }

    public final String toString() {
        return this.a.toString().concat(".reverse()");
    }
}
