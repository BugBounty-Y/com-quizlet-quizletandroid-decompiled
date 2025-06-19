package com.bumptech.glide.util;

import androidx.collection.C0208f;
import androidx.collection.V;

/* loaded from: classes.dex */
public final class c extends C0208f {
    public int g;

    @Override // androidx.collection.V, java.util.Map
    public final void clear() {
        this.g = 0;
        super.clear();
    }

    @Override // androidx.collection.V
    public final void h(V v) {
        this.g = 0;
        super.h(v);
    }

    @Override // androidx.collection.V, java.util.Map
    public final int hashCode() {
        if (this.g == 0) {
            this.g = super.hashCode();
        }
        return this.g;
    }

    @Override // androidx.collection.V
    public final Object i(int i) {
        this.g = 0;
        return super.i(i);
    }

    @Override // androidx.collection.V
    public final Object j(int i, Object obj) {
        this.g = 0;
        return super.j(i, obj);
    }

    @Override // androidx.collection.V, java.util.Map
    public final Object put(Object obj, Object obj2) {
        this.g = 0;
        return super.put(obj, obj2);
    }
}
