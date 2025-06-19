package com.google.android.gms.internal.play_billing;

import java.util.AbstractMap;
import java.util.Objects;

/* loaded from: classes2.dex */
public final class S extends B {
    public final /* synthetic */ T c;

    public S(T t) {
        this.c = t;
    }

    @Override // com.google.android.gms.internal.play_billing.AbstractC3844w
    public final boolean g() {
        return true;
    }

    @Override // java.util.List
    public final /* bridge */ /* synthetic */ Object get(int i) {
        T t = this.c;
        Z0.h(i, t.e);
        int i2 = i + i;
        Object[] objArr = t.d;
        Object obj = objArr[i2];
        Objects.requireNonNull(obj);
        Object obj2 = objArr[i2 + 1];
        Objects.requireNonNull(obj2);
        return new AbstractMap.SimpleImmutableEntry(obj, obj2);
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.List
    public final int size() {
        return this.c.e;
    }
}
