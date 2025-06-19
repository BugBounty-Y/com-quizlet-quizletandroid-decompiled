package com.google.common.collect;

import com.google.android.gms.internal.mlkit_vision_common.AbstractC3502n4;
import java.io.InvalidObjectException;
import java.io.ObjectInputStream;
import java.io.Serializable;
import java.util.Collection;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

/* loaded from: classes2.dex */
public abstract class m implements Map, Serializable {
    public transient z a;
    public transient A b;
    public transient B c;

    public static C b(Serializable serializable, Object obj, Serializable serializable2, Object obj2, Serializable serializable3, Object obj3, Serializable serializable4, Object obj4) {
        AbstractC3502n4.h(serializable, obj);
        AbstractC3502n4.h(serializable2, obj2);
        AbstractC3502n4.h(serializable3, obj3);
        AbstractC3502n4.h(serializable4, obj4);
        return C.d(4, new Object[]{serializable, obj, serializable2, obj2, serializable3, obj3, serializable4, obj4}, null);
    }

    private void readObject(ObjectInputStream objectInputStream) throws InvalidObjectException {
        throw new InvalidObjectException("Use SerializedForm");
    }

    @Override // java.util.Map
    /* renamed from: a, reason: merged with bridge method [inline-methods] */
    public final o entrySet() {
        z zVar = this.a;
        if (zVar != null) {
            return zVar;
        }
        C c = (C) this;
        z zVar2 = new z(c, c.e, c.f);
        this.a = zVar2;
        return zVar2;
    }

    @Override // java.util.Map
    public final void clear() {
        throw new UnsupportedOperationException();
    }

    @Override // java.util.Map
    public final boolean containsKey(Object obj) {
        return get(obj) != null;
    }

    @Override // java.util.Map
    public final boolean containsValue(Object obj) {
        B b = this.c;
        if (b == null) {
            C c = (C) this;
            B b2 = new B(c.e, 1, c.f);
            this.c = b2;
            b = b2;
        }
        return b.contains(obj);
    }

    @Override // java.util.Map
    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof Map) {
            return entrySet().equals(((Map) obj).entrySet());
        }
        return false;
    }

    @Override // java.util.Map
    public abstract Object get(Object obj);

    @Override // java.util.Map
    public final Object getOrDefault(Object obj, Object obj2) {
        Object obj3 = get(obj);
        return obj3 != null ? obj3 : obj2;
    }

    @Override // java.util.Map
    public final int hashCode() {
        Iterator it2 = entrySet().iterator();
        int i = 0;
        while (it2.hasNext()) {
            Object next = it2.next();
            i = ~(~(i + (next != null ? next.hashCode() : 0)));
        }
        return i;
    }

    @Override // java.util.Map
    public final boolean isEmpty() {
        return ((C) this).size() == 0;
    }

    @Override // java.util.Map
    public final Set keySet() {
        A a = this.b;
        if (a != null) {
            return a;
        }
        C c = (C) this;
        A a2 = new A(c, new B(c.e, 0, c.f));
        this.b = a2;
        return a2;
    }

    @Override // java.util.Map
    public final Object put(Object obj, Object obj2) {
        throw new UnsupportedOperationException();
    }

    @Override // java.util.Map
    public final void putAll(Map map) {
        throw new UnsupportedOperationException();
    }

    @Override // java.util.Map
    public final Object remove(Object obj) {
        throw new UnsupportedOperationException();
    }

    public final String toString() {
        int i = ((C) this).f;
        AbstractC3502n4.i(i, "size");
        StringBuilder sb = new StringBuilder((int) Math.min(i * 8, 1073741824L));
        sb.append('{');
        com.google.android.gms.internal.common.g it2 = ((z) entrySet()).iterator();
        boolean z = true;
        while (true) {
            AbstractC3918a abstractC3918a = (AbstractC3918a) it2;
            if (!abstractC3918a.hasNext()) {
                sb.append('}');
                return sb.toString();
            }
            Map.Entry entry = (Map.Entry) abstractC3918a.next();
            if (!z) {
                sb.append(", ");
            }
            sb.append(entry.getKey());
            sb.append('=');
            sb.append(entry.getValue());
            z = false;
        }
    }

    @Override // java.util.Map
    public final Collection values() {
        B b = this.c;
        if (b != null) {
            return b;
        }
        C c = (C) this;
        B b2 = new B(c.e, 1, c.f);
        this.c = b2;
        return b2;
    }

    public Object writeReplace() {
        return new l(this);
    }
}
