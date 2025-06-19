package com.google.android.gms.internal.mlkit_vision_common;

import java.util.AbstractMap;

/* loaded from: classes2.dex */
public final class U4 extends R4 {
    public final /* synthetic */ V4 c;

    public U4(V4 v4) {
        this.c = v4;
    }

    @Override // java.util.List
    public final /* synthetic */ Object get(int i) {
        V4 v4 = this.c;
        N3.f(i, v4.e);
        int i2 = i + i;
        Object[] objArr = v4.d;
        Object obj = objArr[i2];
        obj.getClass();
        Object obj2 = objArr[i2 + 1];
        obj2.getClass();
        return new AbstractMap.SimpleImmutableEntry(obj, obj2);
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.List
    public final int size() {
        return this.c.e;
    }
}
