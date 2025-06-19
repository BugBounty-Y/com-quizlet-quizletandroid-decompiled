package com.google.android.gms.internal.ads;

import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

/* loaded from: classes2.dex */
public final class Ny extends AbstractC2025es implements Map {
    public final Map c;

    public Ny(Map map) {
        super(4);
        this.c = map;
    }

    @Override // java.util.Map
    public final void clear() {
        this.c.clear();
    }

    @Override // java.util.Map
    public final boolean containsKey(Object obj) {
        return obj != null && this.c.containsKey(obj);
    }

    @Override // java.util.Map
    public final boolean containsValue(Object obj) {
        Iterator it2 = ((Ku) entrySet()).iterator();
        it2.getClass();
        if (obj == null) {
            while (it2.hasNext()) {
                if (((Map.Entry) it2.next()).getValue() == null) {
                    return true;
                }
            }
            return false;
        }
        while (it2.hasNext()) {
            if (obj.equals(((Map.Entry) it2.next()).getValue())) {
                return true;
            }
        }
        return false;
    }

    @Override // java.util.Map
    public final Set entrySet() {
        return AbstractC2543qs.t(this.c.entrySet(), new C2763vy(0));
    }

    @Override // java.util.Map
    public final boolean equals(Object obj) {
        return obj != null && AbstractC2025es.s(obj, this);
    }

    @Override // java.util.Map
    public final /* synthetic */ Object get(Object obj) {
        if (obj == null) {
            return null;
        }
        return (List) this.c.get(obj);
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2025es
    public final /* synthetic */ Object h() {
        return this.c;
    }

    @Override // java.util.Map
    public final int hashCode() {
        return AbstractC2543qs.a(entrySet());
    }

    @Override // java.util.Map
    public final boolean isEmpty() {
        Map map = this.c;
        if (map.isEmpty()) {
            return true;
        }
        return map.size() == 1 && map.containsKey(null);
    }

    @Override // java.util.Map
    public final Set keySet() {
        return AbstractC2543qs.t(this.c.keySet(), new C2763vy(1));
    }

    @Override // java.util.Map
    public final Object put(Object obj, Object obj2) {
        return this.c.put(obj, obj2);
    }

    @Override // java.util.Map
    public final void putAll(Map map) {
        this.c.putAll(map);
    }

    @Override // java.util.Map
    public final Object remove(Object obj) {
        return this.c.remove(obj);
    }

    @Override // java.util.Map
    public final int size() {
        Map map = this.c;
        return map.size() - (map.containsKey(null) ? 1 : 0);
    }

    @Override // java.util.Map
    public final Collection values() {
        return this.c.values();
    }
}
