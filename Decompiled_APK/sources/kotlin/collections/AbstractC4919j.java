package kotlin.collections;

import java.util.Collection;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* renamed from: kotlin.collections.j, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public abstract class AbstractC4919j implements Map, kotlin.jvm.internal.markers.a {

    @NotNull
    public static final C4917h a = new C4917h(null);
    private volatile Set<Object> _keys;
    private volatile Collection<Object> _values;

    public abstract Set a();

    public Set b() {
        if (this._keys == null) {
            this._keys = new com.mayakapps.kache.collection.g(this, 1);
        }
        Set<Object> set = this._keys;
        Intrinsics.d(set);
        return set;
    }

    @Override // java.util.Map
    public final void clear() {
        throw new UnsupportedOperationException("Operation is not supported for read-only collection");
    }

    @Override // java.util.Map
    public boolean containsKey(Object obj) {
        return f(obj) != null;
    }

    @Override // java.util.Map
    public boolean containsValue(Object obj) {
        Set setA = a();
        if (setA.isEmpty()) {
            return false;
        }
        Iterator it2 = setA.iterator();
        while (it2.hasNext()) {
            if (Intrinsics.b(((Map.Entry) it2.next()).getValue(), obj)) {
                return true;
            }
        }
        return false;
    }

    public int d() {
        return a().size();
    }

    public Collection e() {
        if (this._values == null) {
            this._values = new androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap.m(this, 1);
        }
        Collection<Object> collection = this._values;
        Intrinsics.d(collection);
        return collection;
    }

    @Override // java.util.Map
    public final /* bridge */ Set entrySet() {
        return a();
    }

    @Override // java.util.Map
    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof Map)) {
            return false;
        }
        Map map = (Map) obj;
        if (d() != map.size()) {
            return false;
        }
        Set<Map.Entry> setEntrySet = map.entrySet();
        if ((setEntrySet instanceof Collection) && setEntrySet.isEmpty()) {
            return true;
        }
        for (Map.Entry entry : setEntrySet) {
            if (entry != null) {
                Object key = entry.getKey();
                Object value = entry.getValue();
                Object obj2 = get(key);
                if (Intrinsics.b(value, obj2) && (obj2 != null || containsKey(key))) {
                }
            }
            return false;
        }
        return true;
    }

    public final Map.Entry f(Object obj) {
        Object next;
        Iterator it2 = a().iterator();
        while (true) {
            if (!it2.hasNext()) {
                next = null;
                break;
            }
            next = it2.next();
            if (Intrinsics.b(((Map.Entry) next).getKey(), obj)) {
                break;
            }
        }
        return (Map.Entry) next;
    }

    @Override // java.util.Map
    public Object get(Object obj) {
        Map.Entry entryF = f(obj);
        if (entryF != null) {
            return entryF.getValue();
        }
        return null;
    }

    @Override // java.util.Map
    public int hashCode() {
        return a().hashCode();
    }

    @Override // java.util.Map
    public final boolean isEmpty() {
        return d() == 0;
    }

    @Override // java.util.Map
    public final /* bridge */ Set keySet() {
        return b();
    }

    @Override // java.util.Map
    public final Object put(Object obj, Object obj2) {
        throw new UnsupportedOperationException("Operation is not supported for read-only collection");
    }

    @Override // java.util.Map
    public final void putAll(Map map) {
        throw new UnsupportedOperationException("Operation is not supported for read-only collection");
    }

    @Override // java.util.Map
    public final Object remove(Object obj) {
        throw new UnsupportedOperationException("Operation is not supported for read-only collection");
    }

    @Override // java.util.Map
    public final /* bridge */ int size() {
        return d();
    }

    public final String toString() {
        return CollectionsKt.S(a(), ", ", "{", "}", new C4918i(this), 24);
    }

    @Override // java.util.Map
    public final /* bridge */ Collection values() {
        return e();
    }
}
