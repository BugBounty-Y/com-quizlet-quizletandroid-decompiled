package com.google.gson.internal;

import java.util.AbstractSet;
import java.util.Iterator;
import java.util.Map;

/* loaded from: classes2.dex */
public final class j extends AbstractSet {
    public final /* synthetic */ int a;
    public final /* synthetic */ m b;

    public /* synthetic */ j(m mVar, int i) {
        this.a = i;
        this.b = mVar;
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
        l lVarA;
        Object obj2;
        Object value;
        switch (this.a) {
            case 0:
                if (!(obj instanceof Map.Entry)) {
                    return false;
                }
                m mVar = this.b;
                Map.Entry entry = (Map.Entry) obj;
                Object key = entry.getKey();
                l lVar = null;
                if (key != null) {
                    try {
                        lVarA = mVar.a(key, false);
                    } catch (ClassCastException unused) {
                    }
                } else {
                    lVarA = null;
                }
                if (lVarA != null && ((obj2 = lVarA.g) == (value = entry.getValue()) || (obj2 != null && obj2.equals(value)))) {
                    lVar = lVarA;
                }
                return lVar != null;
            default:
                return this.b.containsKey(obj);
        }
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.lang.Iterable, java.util.Set
    public final Iterator iterator() {
        switch (this.a) {
            case 0:
                return new i(this.b, 0);
            default:
                return new i(this.b, 1);
        }
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.Set
    public final boolean remove(Object obj) {
        l lVarA;
        Object obj2;
        Object value;
        switch (this.a) {
            case 0:
                if (obj instanceof Map.Entry) {
                    Map.Entry entry = (Map.Entry) obj;
                    m mVar = this.b;
                    Object key = entry.getKey();
                    l lVar = null;
                    if (key != null) {
                        try {
                            lVarA = mVar.a(key, false);
                        } catch (ClassCastException unused) {
                        }
                    } else {
                        lVarA = null;
                    }
                    if (lVarA != null && ((obj2 = lVarA.g) == (value = entry.getValue()) || (obj2 != null && obj2.equals(value)))) {
                        lVar = lVarA;
                    }
                    if (lVar != null) {
                        mVar.d(lVar, true);
                        break;
                    }
                }
                break;
            default:
                m mVar2 = this.b;
                l lVarA2 = null;
                if (obj != null) {
                    try {
                        lVarA2 = mVar2.a(obj, false);
                    } catch (ClassCastException unused2) {
                    }
                }
                if (lVarA2 != null) {
                    mVar2.d(lVarA2, true);
                }
                if (lVarA2 != null) {
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
        return this.b.c;
    }
}
