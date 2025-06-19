package com.google.android.gms.internal.ads;

import android.util.SparseBooleanArray;

/* renamed from: com.google.android.gms.internal.ads.fF, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2049fF {
    public final SparseBooleanArray a;

    public final int a(int i) {
        SparseBooleanArray sparseBooleanArray = this.a;
        AbstractC1795We.f(i, sparseBooleanArray.size());
        return sparseBooleanArray.keyAt(i);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof C2049fF) {
            return this.a.equals(((C2049fF) obj).a);
        }
        return false;
    }

    public final int hashCode() {
        return this.a.hashCode();
    }
}
