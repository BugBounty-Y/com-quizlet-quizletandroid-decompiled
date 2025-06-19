package kotlinx.collections.immutable.implementations.persistentOrderedMap;

import androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap.m;
import java.util.Collection;
import java.util.Map;
import java.util.Set;
import kotlin.collections.AbstractC4919j;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class c extends AbstractC4919j implements kotlinx.collections.immutable.g {
    public static final c e;
    public final Object b;
    public final Object c;
    public final kotlinx.collections.immutable.implementations.immutableMap.c d;

    static {
        kotlinx.collections.immutable.internal.b bVar = kotlinx.collections.immutable.internal.b.a;
        kotlinx.collections.immutable.implementations.immutableMap.c cVar = kotlinx.collections.immutable.implementations.immutableMap.c.d;
        Intrinsics.e(cVar, "null cannot be cast to non-null type kotlinx.collections.immutable.implementations.immutableMap.PersistentHashMap<K of kotlinx.collections.immutable.implementations.immutableMap.PersistentHashMap.Companion.emptyOf, V of kotlinx.collections.immutable.implementations.immutableMap.PersistentHashMap.Companion.emptyOf>");
        e = new c(bVar, bVar, cVar);
    }

    public c(Object obj, Object obj2, kotlinx.collections.immutable.implementations.immutableMap.c hashMap) {
        Intrinsics.checkNotNullParameter(hashMap, "hashMap");
        this.b = obj;
        this.c = obj2;
        this.d = hashMap;
    }

    @Override // kotlin.collections.AbstractC4919j
    public final Set a() {
        return new g(this, 0);
    }

    @Override // kotlin.collections.AbstractC4919j
    public final Set b() {
        return new g(this, 1);
    }

    @Override // kotlin.collections.AbstractC4919j, java.util.Map
    public final boolean containsKey(Object obj) {
        return this.d.containsKey(obj);
    }

    @Override // kotlin.collections.AbstractC4919j
    public final int d() {
        return this.d.size();
    }

    @Override // kotlin.collections.AbstractC4919j
    public final Collection e() {
        return new m(this);
    }

    @Override // kotlin.collections.AbstractC4919j, java.util.Map
    public final boolean equals(Object obj) {
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
        boolean z = map instanceof c;
        kotlinx.collections.immutable.implementations.immutableMap.c cVar = this.d;
        return z ? cVar.b.g(((c) obj).d.b, b.b) : map instanceof d ? cVar.b.g(((d) obj).d.c, b.c) : map instanceof kotlinx.collections.immutable.implementations.immutableMap.c ? cVar.b.g(((kotlinx.collections.immutable.implementations.immutableMap.c) obj).b, b.d) : map instanceof kotlinx.collections.immutable.implementations.immutableMap.d ? cVar.b.g(((kotlinx.collections.immutable.implementations.immutableMap.d) obj).c, b.e) : super.equals(obj);
    }

    @Override // kotlin.collections.AbstractC4919j, java.util.Map
    public final Object get(Object obj) {
        a aVar = (a) this.d.get(obj);
        if (aVar != null) {
            return aVar.a;
        }
        return null;
    }
}
