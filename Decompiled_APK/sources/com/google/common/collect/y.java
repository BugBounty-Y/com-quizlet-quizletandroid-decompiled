package com.google.common.collect;

import java.util.AbstractMap;
import java.util.Objects;

/* loaded from: classes2.dex */
public final class y extends j {
    public final /* synthetic */ z c;

    public y(z zVar) {
        this.c = zVar;
    }

    @Override // java.util.List
    public final Object get(int i) {
        z zVar = this.c;
        com.google.common.base.b.c(i, zVar.f);
        int i2 = i * 2;
        Object[] objArr = zVar.e;
        Object obj = objArr[i2];
        Objects.requireNonNull(obj);
        Object obj2 = objArr[i2 + 1];
        Objects.requireNonNull(obj2);
        return new AbstractMap.SimpleImmutableEntry(obj, obj2);
    }

    @Override // com.google.common.collect.AbstractC3923f
    public final boolean h() {
        return true;
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.List
    public final int size() {
        return this.c.f;
    }

    @Override // com.google.common.collect.j, com.google.common.collect.AbstractC3923f
    public Object writeReplace() {
        return super.writeReplace();
    }
}
