package androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.persistentOrderedSet;

import androidx.compose.runtime.external.kotlinx.collections.immutable.f;
import java.util.Iterator;
import kotlin.collections.AbstractC4925p;

/* loaded from: classes.dex */
public final class b extends AbstractC4925p implements f {
    public static final b e;
    public final Object b;
    public final Object c;
    public final androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap.c d;

    static {
        androidx.compose.runtime.external.kotlinx.collections.immutable.internal.b bVar = androidx.compose.runtime.external.kotlinx.collections.immutable.internal.b.a;
        e = new b(bVar, bVar, androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap.c.d);
    }

    public b(Object obj, Object obj2, androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap.c cVar) {
        this.b = obj;
        this.c = obj2;
        this.d = cVar;
    }

    @Override // kotlin.collections.AbstractC4911b
    public final int a() {
        return this.d.d();
    }

    @Override // kotlin.collections.AbstractC4911b, java.util.Collection, java.util.List
    public final boolean contains(Object obj) {
        return this.d.containsKey(obj);
    }

    @Override // kotlin.collections.AbstractC4925p, java.util.Collection, java.lang.Iterable, java.util.Set
    public final Iterator iterator() {
        return new c(this.b, this.d, 0);
    }
}
