package com.squareup.moshi;

import java.util.AbstractSet;
import java.util.Iterator;
import java.util.Map;

/* loaded from: classes3.dex */
public final class y extends AbstractSet {
    public final /* synthetic */ int a;
    public final /* synthetic */ A b;

    public /* synthetic */ y(A a, int i) {
        this.a = i;
        this.b = a;
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.Set
    public final void clear() {
        switch (this.a) {
            case 0:
                this.b.clear();
                break;
            default:
                this.b.clear();
                break;
        }
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.Set
    public final boolean contains(Object obj) {
        z zVarA;
        Object obj2;
        Object value;
        switch (this.a) {
            case 0:
                if (!(obj instanceof Map.Entry)) {
                    return false;
                }
                A a = this.b;
                Map.Entry entry = (Map.Entry) obj;
                Object key = entry.getKey();
                z zVar = null;
                if (key != null) {
                    try {
                        zVarA = a.a(key, false);
                    } catch (ClassCastException unused) {
                    }
                } else {
                    zVarA = null;
                }
                if (zVarA != null && ((obj2 = zVarA.h) == (value = entry.getValue()) || (obj2 != null && obj2.equals(value)))) {
                    zVar = zVarA;
                }
                return zVar != null;
            default:
                return this.b.containsKey(obj);
        }
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.lang.Iterable, java.util.Set
    public final Iterator iterator() {
        switch (this.a) {
            case 0:
                return new x(this.b, 0);
            default:
                return new x(this.b, 1);
        }
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.Set
    public final boolean remove(Object obj) {
        z zVarA;
        Object obj2;
        Object value;
        switch (this.a) {
            case 0:
                if (obj instanceof Map.Entry) {
                    Map.Entry entry = (Map.Entry) obj;
                    A a = this.b;
                    Object key = entry.getKey();
                    z zVar = null;
                    if (key != null) {
                        try {
                            zVarA = a.a(key, false);
                        } catch (ClassCastException unused) {
                        }
                    } else {
                        zVarA = null;
                    }
                    if (zVarA != null && ((obj2 = zVarA.h) == (value = entry.getValue()) || (obj2 != null && obj2.equals(value)))) {
                        zVar = zVarA;
                    }
                    if (zVar != null) {
                        a.d(zVar, true);
                        break;
                    }
                }
                break;
            default:
                A a2 = this.b;
                z zVarA2 = null;
                if (obj != null) {
                    try {
                        zVarA2 = a2.a(obj, false);
                    } catch (ClassCastException unused2) {
                    }
                }
                if (zVarA2 != null) {
                    a2.d(zVarA2, true);
                }
                if (zVarA2 != null) {
                    break;
                }
                break;
        }
        return true;
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.Set
    public final int size() {
        switch (this.a) {
        }
        return this.b.d;
    }
}
