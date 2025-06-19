package kotlinx.collections.immutable.implementations.immutableMap;

import com.google.android.gms.internal.mlkit_vision_camera.C1;
import java.util.Collection;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import kotlin.collections.AbstractC4922m;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class d extends AbstractC4922m implements kotlinx.collections.immutable.f {
    public c a;
    public kotlinx.collections.immutable.internal.b b;
    public j c;
    public Object d;
    public int e;
    public int f;

    public d(c map) {
        Intrinsics.checkNotNullParameter(map, "map");
        this.a = map;
        this.b = new kotlinx.collections.immutable.internal.b();
        this.c = map.b;
        this.f = map.d();
    }

    @Override // kotlin.collections.AbstractC4922m
    public final Set a() {
        return new f(this);
    }

    @Override // kotlin.collections.AbstractC4922m
    public final Set b() {
        return new kotlin.collections.builders.j(this);
    }

    @Override // java.util.AbstractMap, java.util.Map
    public final void clear() {
        j jVar = j.e;
        j jVar2 = j.e;
        Intrinsics.e(jVar2, "null cannot be cast to non-null type kotlinx.collections.immutable.implementations.immutableMap.TrieNode<K of kotlinx.collections.immutable.implementations.immutableMap.PersistentHashMapBuilder, V of kotlinx.collections.immutable.implementations.immutableMap.PersistentHashMapBuilder>");
        g(jVar2);
        h(0);
    }

    @Override // java.util.AbstractMap, java.util.Map
    public final boolean containsKey(Object obj) {
        return this.c.d(obj != null ? obj.hashCode() : 0, 0, obj);
    }

    @Override // kotlin.collections.AbstractC4922m
    public final int d() {
        return this.f;
    }

    @Override // kotlin.collections.AbstractC4922m
    public final Collection e() {
        return new androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap.j(this);
    }

    @Override // java.util.AbstractMap, java.util.Map
    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof Map)) {
            return false;
        }
        Map otherMap = (Map) obj;
        if (this.f != otherMap.size()) {
            return false;
        }
        if (otherMap instanceof c) {
            return this.c.g(((c) obj).b, b.f);
        }
        if (otherMap instanceof d) {
            return this.c.g(((d) obj).c, b.g);
        }
        if (otherMap instanceof kotlinx.collections.immutable.implementations.persistentOrderedMap.c) {
            j jVar = this.c;
            c cVar = ((kotlinx.collections.immutable.implementations.persistentOrderedMap.c) obj).d;
            return jVar.g(cVar.b, b.h);
        }
        if (otherMap instanceof kotlinx.collections.immutable.implementations.persistentOrderedMap.d) {
            return this.c.g(((kotlinx.collections.immutable.implementations.persistentOrderedMap.d) obj).d.c, b.i);
        }
        Intrinsics.checkNotNullParameter(this, "thisMap");
        Intrinsics.checkNotNullParameter(otherMap, "otherMap");
        if (d() != otherMap.size()) {
            throw new IllegalArgumentException("Failed requirement.");
        }
        if (otherMap.isEmpty()) {
            return true;
        }
        Iterator it2 = otherMap.entrySet().iterator();
        while (it2.hasNext()) {
            if (!C1.a(this, (Map.Entry) it2.next())) {
                return false;
            }
        }
        return true;
    }

    @Override // kotlinx.collections.immutable.f
    /* renamed from: f, reason: merged with bridge method [inline-methods] */
    public final c build() {
        c cVar = this.a;
        if (cVar != null) {
            return cVar;
        }
        c cVar2 = new c(this.c, d());
        this.a = cVar2;
        this.b = new kotlinx.collections.immutable.internal.b();
        return cVar2;
    }

    public final void g(j value) {
        Intrinsics.checkNotNullParameter(value, "value");
        if (value != this.c) {
            this.c = value;
            this.a = null;
        }
    }

    @Override // java.util.AbstractMap, java.util.Map
    public final Object get(Object obj) {
        return this.c.h(obj != null ? obj.hashCode() : 0, 0, obj);
    }

    public final void h(int i) {
        this.f = i;
        this.e++;
    }

    @Override // java.util.AbstractMap, java.util.Map
    public final int hashCode() {
        Intrinsics.checkNotNullParameter(this, "map");
        return entrySet().hashCode();
    }

    @Override // java.util.AbstractMap, java.util.Map
    public final Object put(Object obj, Object obj2) {
        this.d = null;
        g(this.c.m(obj != null ? obj.hashCode() : 0, obj, obj2, 0, this));
        return this.d;
    }

    @Override // java.util.AbstractMap, java.util.Map
    public final void putAll(Map from) {
        Intrinsics.checkNotNullParameter(from, "from");
        if (from.isEmpty()) {
            return;
        }
        c cVarBuild = null;
        c cVar = from instanceof c ? (c) from : null;
        if (cVar == null) {
            d dVar = from instanceof d ? (d) from : null;
            if (dVar != null) {
                cVarBuild = dVar.build();
            }
        } else {
            cVarBuild = cVar;
        }
        if (cVarBuild == null) {
            super.putAll(from);
            return;
        }
        kotlinx.collections.immutable.internal.a aVar = new kotlinx.collections.immutable.internal.a();
        aVar.a = 0;
        int iD = d();
        j jVar = this.c;
        j jVar2 = cVarBuild.b;
        Intrinsics.e(jVar2, "null cannot be cast to non-null type kotlinx.collections.immutable.implementations.immutableMap.TrieNode<K of kotlinx.collections.immutable.implementations.immutableMap.PersistentHashMapBuilder, V of kotlinx.collections.immutable.implementations.immutableMap.PersistentHashMapBuilder>");
        g(jVar.n(jVar2, 0, aVar, this));
        int iD2 = (cVarBuild.d() + iD) - aVar.a;
        if (iD != iD2) {
            h(iD2);
        }
    }

    @Override // java.util.Map
    public final boolean remove(Object obj, Object obj2) {
        int iD = d();
        j jVarP = this.c.p(obj != null ? obj.hashCode() : 0, obj, obj2, 0, this);
        if (jVarP == null) {
            j jVar = j.e;
            jVarP = j.e;
            Intrinsics.e(jVarP, "null cannot be cast to non-null type kotlinx.collections.immutable.implementations.immutableMap.TrieNode<K of kotlinx.collections.immutable.implementations.immutableMap.PersistentHashMapBuilder, V of kotlinx.collections.immutable.implementations.immutableMap.PersistentHashMapBuilder>");
        }
        g(jVarP);
        return iD != d();
    }

    @Override // java.util.AbstractMap, java.util.Map
    public final Object remove(Object obj) {
        this.d = null;
        j jVarO = this.c.o(obj != null ? obj.hashCode() : 0, obj, 0, this);
        if (jVarO == null) {
            j jVar = j.e;
            jVarO = j.e;
            Intrinsics.e(jVarO, "null cannot be cast to non-null type kotlinx.collections.immutable.implementations.immutableMap.TrieNode<K of kotlinx.collections.immutable.implementations.immutableMap.PersistentHashMapBuilder, V of kotlinx.collections.immutable.implementations.immutableMap.PersistentHashMapBuilder>");
        }
        g(jVarO);
        return this.d;
    }
}
