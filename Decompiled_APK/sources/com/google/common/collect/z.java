package com.google.common.collect;

import java.util.Map;

/* loaded from: classes2.dex */
public final class z extends o {
    public final transient m d;
    public final transient Object[] e;
    public final transient int f;

    public z(m mVar, Object[] objArr, int i) {
        this.d = mVar;
        this.e = objArr;
        this.f = i;
    }

    @Override // com.google.common.collect.AbstractC3923f
    public final int b(Object[] objArr) {
        return a().b(objArr);
    }

    @Override // com.google.common.collect.AbstractC3923f, java.util.AbstractCollection, java.util.Collection, java.util.Set
    public final boolean contains(Object obj) {
        if (obj instanceof Map.Entry) {
            Map.Entry entry = (Map.Entry) obj;
            Object key = entry.getKey();
            Object value = entry.getValue();
            if (value != null && value.equals(this.d.get(key))) {
                return true;
            }
        }
        return false;
    }

    @Override // com.google.common.collect.AbstractC3923f
    public final boolean h() {
        return true;
    }

    @Override // com.google.common.collect.AbstractC3923f
    /* renamed from: j */
    public final com.google.android.gms.internal.common.g iterator() {
        return a().listIterator(0);
    }

    @Override // com.google.common.collect.o
    public final j o() {
        return new y(this);
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.Set
    public final int size() {
        return this.f;
    }

    @Override // com.google.common.collect.o, com.google.common.collect.AbstractC3923f
    public Object writeReplace() {
        return super.writeReplace();
    }
}
