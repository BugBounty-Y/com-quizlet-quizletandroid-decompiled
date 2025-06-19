package kotlinx.collections.immutable.implementations.persistentOrderedMap;

import java.util.Iterator;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class h implements Iterator, kotlin.jvm.internal.markers.a {
    public final /* synthetic */ int a;
    public final androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.persistentOrderedSet.c b;

    public h(c map, int i) {
        this.a = i;
        switch (i) {
            case 1:
                Intrinsics.checkNotNullParameter(map, "map");
                this.b = new androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.persistentOrderedSet.c(map.b, map.d, 1);
                break;
            case 2:
                Intrinsics.checkNotNullParameter(map, "map");
                this.b = new androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.persistentOrderedSet.c(map.b, map.d, 1);
                break;
            default:
                Intrinsics.checkNotNullParameter(map, "map");
                this.b = new androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.persistentOrderedSet.c(map.b, map.d, 1);
                break;
        }
    }

    @Override // java.util.Iterator
    public final boolean hasNext() {
        switch (this.a) {
        }
        return this.b.hasNext();
    }

    @Override // java.util.Iterator
    public final Object next() {
        switch (this.a) {
            case 0:
                androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.persistentOrderedSet.c cVar = this.b;
                return new androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap.a(1, cVar.b, cVar.a().a);
            case 1:
                androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.persistentOrderedSet.c cVar2 = this.b;
                Object obj = cVar2.b;
                cVar2.a();
                return obj;
            default:
                return this.b.a().a;
        }
    }

    @Override // java.util.Iterator
    public final void remove() {
        switch (this.a) {
            case 0:
                throw new UnsupportedOperationException("Operation is not supported for read-only collection");
            case 1:
                throw new UnsupportedOperationException("Operation is not supported for read-only collection");
            default:
                throw new UnsupportedOperationException("Operation is not supported for read-only collection");
        }
    }
}
