package kotlin.collections.builders;

import androidx.compose.runtime.snapshots.w;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3324c;
import java.io.NotSerializableException;
import java.io.Serializable;
import java.util.AbstractList;
import java.util.Arrays;
import java.util.Collection;
import java.util.ConcurrentModificationException;
import java.util.Iterator;
import java.util.List;
import java.util.ListIterator;
import java.util.RandomAccess;
import kotlin.collections.A;
import kotlin.collections.AbstractC4916g;
import kotlin.collections.AbstractC4921l;
import kotlin.collections.C4913d;
import kotlin.collections.C4930v;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b extends AbstractC4921l implements RandomAccess, Serializable {
    public Object[] a;
    public final int b;
    public int c;
    public final b d;
    public final d e;

    public b(Object[] backing, int i, int i2, b bVar, d root) {
        Intrinsics.checkNotNullParameter(backing, "backing");
        Intrinsics.checkNotNullParameter(root, "root");
        this.a = backing;
        this.b = i;
        this.c = i2;
        this.d = bVar;
        this.e = root;
        ((AbstractList) this).modCount = ((AbstractList) root).modCount;
    }

    private final Object writeReplace() throws NotSerializableException {
        if (this.e.c) {
            return new l(0, this);
        }
        throw new NotSerializableException("The list cannot be serialized while it is being built.");
    }

    @Override // kotlin.collections.AbstractC4921l
    public final int a() {
        j();
        return this.c;
    }

    @Override // java.util.AbstractList, java.util.AbstractCollection, java.util.Collection, java.util.List
    public final boolean add(Object obj) {
        k();
        j();
        h(this.b + this.c, obj);
        return true;
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.List
    public final boolean addAll(Collection elements) {
        Intrinsics.checkNotNullParameter(elements, "elements");
        k();
        j();
        int size = elements.size();
        g(this.b + this.c, elements, size);
        return size > 0;
    }

    @Override // kotlin.collections.AbstractC4921l
    public final Object b(int i) {
        k();
        j();
        C4913d c4913d = AbstractC4916g.a;
        int i2 = this.c;
        c4913d.getClass();
        C4913d.b(i, i2);
        return m(this.b + i);
    }

    @Override // java.util.AbstractList, java.util.AbstractCollection, java.util.Collection, java.util.List
    public final void clear() {
        k();
        j();
        n(this.b, this.c);
    }

    @Override // java.util.AbstractList, java.util.Collection, java.util.List
    public final boolean equals(Object obj) {
        j();
        if (obj == this) {
            return true;
        }
        if (obj instanceof List) {
            return AbstractC3324c.b(this.a, this.b, this.c, (List) obj);
        }
        return false;
    }

    public final void g(int i, Collection collection, int i2) {
        ((AbstractList) this).modCount++;
        d dVar = this.e;
        b bVar = this.d;
        if (bVar != null) {
            bVar.g(i, collection, i2);
        } else {
            d dVar2 = d.e;
            dVar.g(i, collection, i2);
        }
        this.a = dVar.a;
        this.c += i2;
    }

    @Override // java.util.AbstractList, java.util.List
    public final Object get(int i) {
        j();
        C4913d c4913d = AbstractC4916g.a;
        int i2 = this.c;
        c4913d.getClass();
        C4913d.b(i, i2);
        return this.a[this.b + i];
    }

    public final void h(int i, Object obj) {
        ((AbstractList) this).modCount++;
        d dVar = this.e;
        b bVar = this.d;
        if (bVar != null) {
            bVar.h(i, obj);
        } else {
            d dVar2 = d.e;
            dVar.h(i, obj);
        }
        this.a = dVar.a;
        this.c++;
    }

    @Override // java.util.AbstractList, java.util.Collection, java.util.List
    public final int hashCode() {
        j();
        Object[] objArr = this.a;
        int i = this.c;
        int iHashCode = 1;
        for (int i2 = 0; i2 < i; i2++) {
            Object obj = objArr[this.b + i2];
            iHashCode = (iHashCode * 31) + (obj != null ? obj.hashCode() : 0);
        }
        return iHashCode;
    }

    @Override // java.util.AbstractList, java.util.List
    public final int indexOf(Object obj) {
        j();
        for (int i = 0; i < this.c; i++) {
            if (Intrinsics.b(this.a[this.b + i], obj)) {
                return i;
            }
        }
        return -1;
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.List
    public final boolean isEmpty() {
        j();
        return this.c == 0;
    }

    @Override // java.util.AbstractList, java.util.AbstractCollection, java.util.Collection, java.lang.Iterable, java.util.List
    public final Iterator iterator() {
        return listIterator(0);
    }

    public final void j() {
        if (((AbstractList) this.e).modCount != ((AbstractList) this).modCount) {
            throw new ConcurrentModificationException();
        }
    }

    public final void k() {
        if (this.e.c) {
            throw new UnsupportedOperationException();
        }
    }

    @Override // java.util.AbstractList, java.util.List
    public final int lastIndexOf(Object obj) {
        j();
        for (int i = this.c - 1; i >= 0; i--) {
            if (Intrinsics.b(this.a[this.b + i], obj)) {
                return i;
            }
        }
        return -1;
    }

    @Override // java.util.AbstractList, java.util.List
    public final ListIterator listIterator() {
        return listIterator(0);
    }

    public final Object m(int i) {
        Object objM;
        ((AbstractList) this).modCount++;
        b bVar = this.d;
        if (bVar != null) {
            objM = bVar.m(i);
        } else {
            d dVar = d.e;
            objM = this.e.m(i);
        }
        this.c--;
        return objM;
    }

    public final void n(int i, int i2) {
        if (i2 > 0) {
            ((AbstractList) this).modCount++;
        }
        b bVar = this.d;
        if (bVar != null) {
            bVar.n(i, i2);
        } else {
            d dVar = d.e;
            this.e.n(i, i2);
        }
        this.c -= i2;
    }

    public final int o(int i, int i2, Collection collection, boolean z) {
        int iO;
        b bVar = this.d;
        if (bVar != null) {
            iO = bVar.o(i, i2, collection, z);
        } else {
            d dVar = d.e;
            iO = this.e.o(i, i2, collection, z);
        }
        if (iO > 0) {
            ((AbstractList) this).modCount++;
        }
        this.c -= iO;
        return iO;
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.List
    public final boolean remove(Object obj) {
        k();
        j();
        int iIndexOf = indexOf(obj);
        if (iIndexOf >= 0) {
            b(iIndexOf);
        }
        return iIndexOf >= 0;
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.List
    public final boolean removeAll(Collection elements) {
        Intrinsics.checkNotNullParameter(elements, "elements");
        k();
        j();
        return o(this.b, this.c, elements, false) > 0;
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.List
    public final boolean retainAll(Collection elements) {
        Intrinsics.checkNotNullParameter(elements, "elements");
        k();
        j();
        return o(this.b, this.c, elements, true) > 0;
    }

    @Override // java.util.AbstractList, java.util.List
    public final Object set(int i, Object obj) {
        k();
        j();
        C4913d c4913d = AbstractC4916g.a;
        int i2 = this.c;
        c4913d.getClass();
        C4913d.b(i, i2);
        Object[] objArr = this.a;
        int i3 = this.b + i;
        Object obj2 = objArr[i3];
        objArr[i3] = obj;
        return obj2;
    }

    @Override // java.util.AbstractList, java.util.List
    public final List subList(int i, int i2) {
        C4913d c4913d = AbstractC4916g.a;
        int i3 = this.c;
        c4913d.getClass();
        C4913d.d(i, i2, i3);
        return new b(this.a, this.b + i, i2 - i, this, this.e);
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.List
    public final Object[] toArray(Object[] array) {
        Intrinsics.checkNotNullParameter(array, "array");
        j();
        int length = array.length;
        int i = this.c;
        int i2 = this.b;
        if (length < i) {
            Object[] objArrCopyOfRange = Arrays.copyOfRange(this.a, i2, i + i2, array.getClass());
            Intrinsics.checkNotNullExpressionValue(objArrCopyOfRange, "copyOfRange(...)");
            return objArrCopyOfRange;
        }
        C4930v.h(this.a, 0, array, i2, i + i2);
        A.e(this.c, array);
        return array;
    }

    @Override // java.util.AbstractCollection
    public final String toString() {
        j();
        return AbstractC3324c.c(this.a, this.b, this.c, this);
    }

    @Override // java.util.AbstractList, java.util.List
    public final ListIterator listIterator(int i) {
        j();
        C4913d c4913d = AbstractC4916g.a;
        int i2 = this.c;
        c4913d.getClass();
        C4913d.c(i, i2);
        return new w(this, i);
    }

    @Override // java.util.AbstractList, java.util.List
    public final void add(int i, Object obj) {
        k();
        j();
        C4913d c4913d = AbstractC4916g.a;
        int i2 = this.c;
        c4913d.getClass();
        C4913d.c(i, i2);
        h(this.b + i, obj);
    }

    @Override // java.util.AbstractList, java.util.List
    public final boolean addAll(int i, Collection elements) {
        Intrinsics.checkNotNullParameter(elements, "elements");
        k();
        j();
        C4913d c4913d = AbstractC4916g.a;
        int i2 = this.c;
        c4913d.getClass();
        C4913d.c(i, i2);
        int size = elements.size();
        g(this.b + i, elements, size);
        return size > 0;
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.List
    public final Object[] toArray() {
        j();
        Object[] objArr = this.a;
        int i = this.c;
        int i2 = this.b;
        return C4930v.n(i2, i + i2, objArr);
    }
}
