package kotlin.collections.builders;

import java.util.Collection;
import java.util.Iterator;
import java.util.Map;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class i extends a {
    public final h a;

    public i(h backing) {
        Intrinsics.checkNotNullParameter(backing, "backing");
        this.a = backing;
    }

    @Override // kotlin.collections.AbstractC4923n
    public final int a() {
        return this.a.i;
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.Set
    public final boolean add(Object obj) {
        Map.Entry element = (Map.Entry) obj;
        Intrinsics.checkNotNullParameter(element, "element");
        throw new UnsupportedOperationException();
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.Set
    public final boolean addAll(Collection elements) {
        Intrinsics.checkNotNullParameter(elements, "elements");
        throw new UnsupportedOperationException();
    }

    @Override // kotlin.collections.builders.a
    public final boolean b(Map.Entry element) {
        Intrinsics.checkNotNullParameter(element, "element");
        return this.a.g(element);
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.Set
    public final void clear() {
        this.a.clear();
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.Set
    public final boolean containsAll(Collection elements) {
        Intrinsics.checkNotNullParameter(elements, "elements");
        return this.a.f(elements);
    }

    @Override // kotlin.collections.builders.a
    public final boolean e(Map.Entry entry) {
        Intrinsics.checkNotNullParameter(entry, "element");
        h hVar = this.a;
        hVar.getClass();
        Intrinsics.checkNotNullParameter(entry, "entry");
        hVar.d();
        int iJ = hVar.j(entry.getKey());
        if (iJ < 0) {
            return false;
        }
        Object[] objArr = hVar.b;
        Intrinsics.d(objArr);
        if (!Intrinsics.b(objArr[iJ], entry.getValue())) {
            return false;
        }
        hVar.n(iJ);
        return true;
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.Set
    public final boolean isEmpty() {
        return this.a.isEmpty();
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.lang.Iterable, java.util.Set
    public final Iterator iterator() {
        h map = this.a;
        map.getClass();
        Intrinsics.checkNotNullParameter(map, "map");
        return new f(map, 0);
    }

    @Override // java.util.AbstractSet, java.util.AbstractCollection, java.util.Collection, java.util.Set
    public final boolean removeAll(Collection elements) {
        Intrinsics.checkNotNullParameter(elements, "elements");
        this.a.d();
        return super.removeAll(elements);
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.Set
    public final boolean retainAll(Collection elements) {
        Intrinsics.checkNotNullParameter(elements, "elements");
        this.a.d();
        return super.retainAll(elements);
    }
}
