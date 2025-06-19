package kotlin.collections.builders;

import java.util.Collection;
import java.util.Iterator;
import kotlin.collections.AbstractC4923n;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class j extends AbstractC4923n {
    public final /* synthetic */ int a = 0;
    public final Object b;

    public j(h backing) {
        Intrinsics.checkNotNullParameter(backing, "backing");
        this.b = backing;
    }

    @Override // kotlin.collections.AbstractC4923n
    public final int a() {
        switch (this.a) {
            case 0:
                return ((h) this.b).i;
            case 1:
                return ((kotlinx.collections.immutable.implementations.immutableMap.d) this.b).d();
            default:
                return ((kotlinx.collections.immutable.implementations.persistentOrderedMap.d) this.b).d.d();
        }
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.Set
    public final boolean add(Object obj) {
        switch (this.a) {
            case 0:
                throw new UnsupportedOperationException();
            case 1:
                throw new UnsupportedOperationException();
            default:
                throw new UnsupportedOperationException();
        }
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.Set
    public boolean addAll(Collection elements) {
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter(elements, "elements");
                throw new UnsupportedOperationException();
            default:
                return super.addAll(elements);
        }
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.Set
    public final void clear() {
        switch (this.a) {
            case 0:
                ((h) this.b).clear();
                break;
            case 1:
                ((kotlinx.collections.immutable.implementations.immutableMap.d) this.b).clear();
                break;
            default:
                ((kotlinx.collections.immutable.implementations.persistentOrderedMap.d) this.b).clear();
                break;
        }
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.Set
    public final boolean contains(Object obj) {
        switch (this.a) {
            case 0:
                return ((h) this.b).containsKey(obj);
            case 1:
                return ((kotlinx.collections.immutable.implementations.immutableMap.d) this.b).containsKey(obj);
            default:
                return ((kotlinx.collections.immutable.implementations.persistentOrderedMap.d) this.b).d.containsKey(obj);
        }
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.Set
    public boolean isEmpty() {
        switch (this.a) {
            case 0:
                return ((h) this.b).isEmpty();
            default:
                return super.isEmpty();
        }
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.lang.Iterable, java.util.Set
    public final Iterator iterator() {
        switch (this.a) {
            case 0:
                h map = (h) this.b;
                map.getClass();
                Intrinsics.checkNotNullParameter(map, "map");
                return new f(map, 1);
            case 1:
                kotlinx.collections.immutable.implementations.immutableMap.d builder = (kotlinx.collections.immutable.implementations.immutableMap.d) this.b;
                Intrinsics.checkNotNullParameter(builder, "builder");
                androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap.o[] oVarArr = new androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap.o[8];
                for (int i = 0; i < 8; i++) {
                    oVarArr[i] = new kotlinx.collections.immutable.implementations.immutableMap.k(1);
                }
                return new kotlinx.collections.immutable.implementations.immutableMap.g(builder, oVarArr);
            default:
                return new kotlinx.collections.immutable.implementations.persistentOrderedMap.e((kotlinx.collections.immutable.implementations.persistentOrderedMap.d) this.b, 1);
        }
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.Set
    public final boolean remove(Object obj) {
        switch (this.a) {
            case 0:
                h hVar = (h) this.b;
                hVar.d();
                int iJ = hVar.j(obj);
                if (iJ >= 0) {
                    hVar.n(iJ);
                    break;
                }
                break;
            case 1:
                kotlinx.collections.immutable.implementations.immutableMap.d dVar = (kotlinx.collections.immutable.implementations.immutableMap.d) this.b;
                if (dVar.containsKey(obj)) {
                    dVar.remove(obj);
                    break;
                }
                break;
            default:
                kotlinx.collections.immutable.implementations.persistentOrderedMap.d dVar2 = (kotlinx.collections.immutable.implementations.persistentOrderedMap.d) this.b;
                if (dVar2.d.containsKey(obj)) {
                    dVar2.remove(obj);
                    break;
                }
                break;
        }
        return true;
    }

    @Override // java.util.AbstractSet, java.util.AbstractCollection, java.util.Collection, java.util.Set
    public boolean removeAll(Collection elements) {
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter(elements, "elements");
                ((h) this.b).d();
                return super.removeAll(elements);
            default:
                return super.removeAll(elements);
        }
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.Set
    public boolean retainAll(Collection elements) {
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter(elements, "elements");
                ((h) this.b).d();
                break;
        }
        return super.retainAll(elements);
    }

    public j(kotlinx.collections.immutable.implementations.immutableMap.d builder) {
        Intrinsics.checkNotNullParameter(builder, "builder");
        this.b = builder;
    }

    public j(kotlinx.collections.immutable.implementations.persistentOrderedMap.d builder) {
        Intrinsics.checkNotNullParameter(builder, "builder");
        this.b = builder;
    }
}
