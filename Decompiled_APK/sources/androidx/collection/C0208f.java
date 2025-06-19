package androidx.collection;

import java.util.Collection;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

/* renamed from: androidx.collection.f, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public class C0208f extends V implements Map {
    public C0203a d;
    public C0205c e;
    public C0207e f;

    public C0208f() {
        super(0);
    }

    @Override // java.util.Map
    public final Set entrySet() {
        C0203a c0203a = this.d;
        if (c0203a != null) {
            return c0203a;
        }
        C0203a c0203a2 = new C0203a(0, this);
        this.d = c0203a2;
        return c0203a2;
    }

    @Override // java.util.Map
    public final Set keySet() {
        C0205c c0205c = this.e;
        if (c0205c != null) {
            return c0205c;
        }
        C0205c c0205c2 = new C0205c(this);
        this.e = c0205c2;
        return c0205c2;
    }

    public final boolean l(Collection collection) {
        Iterator it2 = collection.iterator();
        while (it2.hasNext()) {
            if (!super.containsKey(it2.next())) {
                return false;
            }
        }
        return true;
    }

    public final boolean m(Collection collection) {
        int i = this.c;
        Iterator it2 = collection.iterator();
        while (it2.hasNext()) {
            super.remove(it2.next());
        }
        return i != this.c;
    }

    public final boolean n(Collection collection) {
        int i = this.c;
        for (int i2 = i - 1; i2 >= 0; i2--) {
            if (!collection.contains(g(i2))) {
                i(i2);
            }
        }
        return i != this.c;
    }

    @Override // java.util.Map
    public final void putAll(Map map) {
        b(map.size() + this.c);
        for (Map.Entry entry : map.entrySet()) {
            put(entry.getKey(), entry.getValue());
        }
    }

    @Override // java.util.Map
    public final Collection values() {
        C0207e c0207e = this.f;
        if (c0207e != null) {
            return c0207e;
        }
        C0207e c0207e2 = new C0207e(this);
        this.f = c0207e2;
        return c0207e2;
    }
}
