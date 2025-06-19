package androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap;

import java.util.Collection;
import java.util.Iterator;
import kotlin.collections.AbstractC4920k;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class j extends AbstractC4920k {
    public final /* synthetic */ int a = 0;
    public final Object b;

    public j(e eVar) {
        this.b = eVar;
    }

    @Override // kotlin.collections.AbstractC4920k
    public final int a() {
        switch (this.a) {
            case 0:
                return ((e) this.b).d();
            case 1:
                return ((kotlin.collections.builders.h) this.b).i;
            case 2:
                return ((kotlinx.collections.immutable.implementations.immutableMap.d) this.b).d();
            default:
                return ((kotlinx.collections.immutable.implementations.persistentOrderedMap.d) this.b).d.d();
        }
    }

    @Override // java.util.AbstractCollection, java.util.Collection
    public final boolean add(Object obj) {
        switch (this.a) {
            case 0:
                throw new UnsupportedOperationException();
            case 1:
                throw new UnsupportedOperationException();
            case 2:
                throw new UnsupportedOperationException();
            default:
                throw new UnsupportedOperationException();
        }
    }

    @Override // java.util.AbstractCollection, java.util.Collection
    public boolean addAll(Collection elements) {
        switch (this.a) {
            case 1:
                Intrinsics.checkNotNullParameter(elements, "elements");
                throw new UnsupportedOperationException();
            default:
                return super.addAll(elements);
        }
    }

    @Override // java.util.AbstractCollection, java.util.Collection
    public final void clear() {
        switch (this.a) {
            case 0:
                ((e) this.b).clear();
                break;
            case 1:
                ((kotlin.collections.builders.h) this.b).clear();
                break;
            case 2:
                ((kotlinx.collections.immutable.implementations.immutableMap.d) this.b).clear();
                break;
            default:
                ((kotlinx.collections.immutable.implementations.persistentOrderedMap.d) this.b).clear();
                break;
        }
    }

    @Override // java.util.AbstractCollection, java.util.Collection
    public final boolean contains(Object obj) {
        switch (this.a) {
            case 0:
                return ((e) this.b).containsValue(obj);
            case 1:
                return ((kotlin.collections.builders.h) this.b).containsValue(obj);
            case 2:
                return ((kotlinx.collections.immutable.implementations.immutableMap.d) this.b).containsValue(obj);
            default:
                return ((kotlinx.collections.immutable.implementations.persistentOrderedMap.d) this.b).containsValue(obj);
        }
    }

    @Override // java.util.AbstractCollection, java.util.Collection
    public boolean isEmpty() {
        switch (this.a) {
            case 1:
                return ((kotlin.collections.builders.h) this.b).isEmpty();
            default:
                return super.isEmpty();
        }
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.lang.Iterable
    public final Iterator iterator() {
        switch (this.a) {
            case 0:
                o[] oVarArr = new o[8];
                for (int i = 0; i < 8; i++) {
                    oVarArr[i] = new p(2);
                }
                return new i((e) this.b, oVarArr);
            case 1:
                kotlin.collections.builders.h map = (kotlin.collections.builders.h) this.b;
                map.getClass();
                Intrinsics.checkNotNullParameter(map, "map");
                return new kotlin.collections.builders.f(map, 2);
            case 2:
                kotlinx.collections.immutable.implementations.immutableMap.d builder = (kotlinx.collections.immutable.implementations.immutableMap.d) this.b;
                Intrinsics.checkNotNullParameter(builder, "builder");
                o[] oVarArr2 = new o[8];
                for (int i2 = 0; i2 < 8; i2++) {
                    oVarArr2[i2] = new kotlinx.collections.immutable.implementations.immutableMap.k(2);
                }
                return new kotlinx.collections.immutable.implementations.immutableMap.g(builder, oVarArr2);
            default:
                return new kotlinx.collections.immutable.implementations.persistentOrderedMap.e((kotlinx.collections.immutable.implementations.persistentOrderedMap.d) this.b, 2);
        }
    }

    @Override // java.util.AbstractCollection, java.util.Collection
    public boolean remove(Object obj) {
        switch (this.a) {
            case 1:
                kotlin.collections.builders.h hVar = (kotlin.collections.builders.h) this.b;
                hVar.d();
                int iK = hVar.k(obj);
                if (iK < 0) {
                    return false;
                }
                hVar.n(iK);
                return true;
            default:
                return super.remove(obj);
        }
    }

    @Override // java.util.AbstractCollection, java.util.Collection
    public boolean removeAll(Collection elements) {
        switch (this.a) {
            case 1:
                Intrinsics.checkNotNullParameter(elements, "elements");
                ((kotlin.collections.builders.h) this.b).d();
                break;
        }
        return super.removeAll(elements);
    }

    @Override // java.util.AbstractCollection, java.util.Collection
    public boolean retainAll(Collection elements) {
        switch (this.a) {
            case 1:
                Intrinsics.checkNotNullParameter(elements, "elements");
                ((kotlin.collections.builders.h) this.b).d();
                break;
        }
        return super.retainAll(elements);
    }

    public j(kotlin.collections.builders.h backing) {
        Intrinsics.checkNotNullParameter(backing, "backing");
        this.b = backing;
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
