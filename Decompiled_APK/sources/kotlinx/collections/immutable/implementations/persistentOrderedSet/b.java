package kotlinx.collections.immutable.implementations.persistentOrderedSet;

import com.quizlet.ui.compose.C4830x;
import java.util.Iterator;
import java.util.Set;
import kotlin.collections.AbstractC4925p;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b extends AbstractC4925p implements kotlinx.collections.immutable.c {
    public static final b e;
    public final Object b;
    public final Object c;
    public final kotlinx.collections.immutable.implementations.immutableMap.c d;

    static {
        kotlinx.collections.immutable.internal.b bVar = kotlinx.collections.immutable.internal.b.a;
        kotlinx.collections.immutable.implementations.immutableMap.c cVar = kotlinx.collections.immutable.implementations.immutableMap.c.d;
        Intrinsics.e(cVar, "null cannot be cast to non-null type kotlinx.collections.immutable.implementations.immutableMap.PersistentHashMap<K of kotlinx.collections.immutable.implementations.immutableMap.PersistentHashMap.Companion.emptyOf, V of kotlinx.collections.immutable.implementations.immutableMap.PersistentHashMap.Companion.emptyOf>");
        e = new b(bVar, bVar, cVar);
    }

    public b(Object obj, Object obj2, kotlinx.collections.immutable.implementations.immutableMap.c hashMap) {
        Intrinsics.checkNotNullParameter(hashMap, "hashMap");
        this.b = obj;
        this.c = obj2;
        this.d = hashMap;
    }

    @Override // kotlin.collections.AbstractC4911b
    public final int a() {
        return this.d.d();
    }

    @Override // kotlin.collections.AbstractC4911b, java.util.Collection, java.util.List
    public final boolean contains(Object obj) {
        return this.d.containsKey(obj);
    }

    @Override // kotlin.collections.AbstractC4925p, java.util.Collection, java.util.Set
    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof Set)) {
            return false;
        }
        Set set = (Set) obj;
        if (a() != set.size()) {
            return false;
        }
        boolean z = set instanceof b;
        kotlinx.collections.immutable.implementations.immutableMap.c cVar = this.d;
        return z ? cVar.b.g(((b) obj).d.b, new C4830x(11, (byte) 0)) : set instanceof c ? cVar.b.g(((c) obj).d.c, new C4830x(12, (byte) 0)) : super.equals(obj);
    }

    @Override // kotlin.collections.AbstractC4925p, java.util.Collection, java.lang.Iterable, java.util.Set
    public final Iterator iterator() {
        return new androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.persistentOrderedSet.c(this.b, this.d, 2);
    }
}
