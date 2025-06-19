package com.google.android.gms.internal.fido;

import java.io.Serializable;
import java.util.Comparator;

/* renamed from: com.google.android.gms.internal.fido.g, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2943g extends AbstractC2958w implements Serializable {
    public final Comparator a;

    public C2943g(Comparator comparator) {
        comparator.getClass();
        this.a = comparator;
    }

    @Override // java.util.Comparator
    public final int compare(Object obj, Object obj2) {
        return this.a.compare(obj, obj2);
    }

    @Override // java.util.Comparator
    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof C2943g) {
            return this.a.equals(((C2943g) obj).a);
        }
        return false;
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return this.a.toString();
    }
}
