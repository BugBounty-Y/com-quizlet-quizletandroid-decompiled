package androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap;

import java.util.Collection;
import java.util.Map;
import java.util.Set;
import kotlin.collections.AbstractC4922m;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public class e extends AbstractC4922m implements androidx.compose.runtime.external.kotlinx.collections.immutable.d {
    public c a;
    public androidx.compose.runtime.external.kotlinx.collections.immutable.internal.b b = new androidx.compose.runtime.external.kotlinx.collections.immutable.internal.b();
    public n c;
    public Object d;
    public int e;
    public int f;

    public e(c cVar) {
        this.a = cVar;
        this.c = cVar.b;
        this.f = cVar.d();
    }

    @Override // kotlin.collections.AbstractC4922m
    public final Set a() {
        return new g(0, this);
    }

    @Override // kotlin.collections.AbstractC4922m
    public final Set b() {
        return new g(1, this);
    }

    @Override // java.util.AbstractMap, java.util.Map
    public final void clear() {
        this.c = n.e;
        g(0);
    }

    @Override // java.util.AbstractMap, java.util.Map
    public boolean containsKey(Object obj) {
        return this.c.d(obj != null ? obj.hashCode() : 0, 0, obj);
    }

    @Override // kotlin.collections.AbstractC4922m
    public final int d() {
        return this.f;
    }

    @Override // kotlin.collections.AbstractC4922m
    public final Collection e() {
        return new j(this);
    }

    @Override // androidx.compose.runtime.external.kotlinx.collections.immutable.d
    /* renamed from: f, reason: merged with bridge method [inline-methods] */
    public c build() {
        n nVar = this.c;
        c cVar = this.a;
        if (nVar != cVar.b) {
            this.b = new androidx.compose.runtime.external.kotlinx.collections.immutable.internal.b();
            cVar = new c(this.c, d());
        }
        this.a = cVar;
        return cVar;
    }

    public final void g(int i) {
        this.f = i;
        this.e++;
    }

    @Override // java.util.AbstractMap, java.util.Map
    public Object get(Object obj) {
        return this.c.g(obj != null ? obj.hashCode() : 0, 0, obj);
    }

    @Override // java.util.AbstractMap, java.util.Map
    public final Object put(Object obj, Object obj2) {
        this.d = null;
        this.c = this.c.l(obj != null ? obj.hashCode() : 0, obj, obj2, 0, this);
        return this.d;
    }

    @Override // java.util.AbstractMap, java.util.Map
    public final void putAll(Map map) {
        c cVarBuild = null;
        c cVar = map instanceof c ? (c) map : null;
        if (cVar == null) {
            e eVar = map instanceof e ? (e) map : null;
            if (eVar != null) {
                cVarBuild = eVar.build();
            }
        } else {
            cVarBuild = cVar;
        }
        if (cVarBuild == null) {
            super.putAll(map);
            return;
        }
        androidx.compose.runtime.external.kotlinx.collections.immutable.internal.a aVar = new androidx.compose.runtime.external.kotlinx.collections.immutable.internal.a();
        aVar.a = 0;
        int i = this.f;
        n nVar = this.c;
        n nVar2 = cVarBuild.b;
        Intrinsics.e(nVar2, "null cannot be cast to non-null type androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap.TrieNode<K of androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap.PersistentHashMapBuilder, V of androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap.PersistentHashMapBuilder>");
        this.c = nVar.m(nVar2, 0, aVar, this);
        int i2 = (cVarBuild.c + i) - aVar.a;
        if (i != i2) {
            g(i2);
        }
    }

    @Override // java.util.Map
    public final boolean remove(Object obj, Object obj2) {
        int iD = d();
        n nVarO = this.c.o(obj != null ? obj.hashCode() : 0, obj, obj2, 0, this);
        if (nVarO == null) {
            nVarO = n.e;
        }
        this.c = nVarO;
        return iD != d();
    }

    @Override // java.util.AbstractMap, java.util.Map
    public Object remove(Object obj) {
        this.d = null;
        n nVarN = this.c.n(obj != null ? obj.hashCode() : 0, obj, 0, this);
        if (nVarN == null) {
            nVarN = n.e;
        }
        this.c = nVarN;
        return this.d;
    }
}
