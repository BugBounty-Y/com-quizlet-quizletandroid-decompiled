package com.google.android.gms.internal.mlkit_common;

import com.google.android.gms.internal.mlkit_vision_common.E3;
import java.util.AbstractMap;
import java.util.Objects;

/* loaded from: classes2.dex */
public final class h extends d {
    public final /* synthetic */ i c;

    public h(i iVar) {
        this.c = iVar;
    }

    @Override // java.util.List
    public final /* bridge */ /* synthetic */ Object get(int i) {
        i iVar = this.c;
        E3.a(i, iVar.e);
        int i2 = i + i;
        Object[] objArr = iVar.d;
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
