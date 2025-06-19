package kotlin.collections.builders;

import androidx.compose.runtime.snapshots.w;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3324c;
import java.io.NotSerializableException;
import java.io.Serializable;
import java.util.AbstractList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.ListIterator;
import java.util.RandomAccess;
import kotlin.collections.A;
import kotlin.collections.AbstractC4916g;
import kotlin.collections.AbstractC4921l;
import kotlin.collections.C4913d;
import kotlin.collections.C4930v;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes3.dex */
public final class d extends AbstractC4921l implements List, RandomAccess, Serializable {

    @NotNull
    private static final c d = new c(null);
    public static final d e;
    public Object[] a;
    public int b;
    public boolean c;

    static {
        d dVar = new d(0);
        dVar.c = true;
        e = dVar;
    }

    public d() {
        this(0, 1, null);
    }

    private final Object writeReplace() throws NotSerializableException {
        if (this.c) {
            return new l(0, this);
        }
        throw new NotSerializableException("The list cannot be serialized while it is being built.");
    }

    @Override // kotlin.collections.AbstractC4921l
    public final int a() {
        return this.b;
    }

    @Override // java.util.AbstractList, java.util.AbstractCollection, java.util.Collection, java.util.List
    public final boolean add(Object obj) {
        j();
        int i = this.b;
        ((AbstractList) this).modCount++;
        k(i, 1);
        this.a[i] = obj;
        return true;
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.List
    public final boolean addAll(Collection elements) {
        Intrinsics.checkNotNullParameter(elements, "elements");
        j();
        int size = elements.size();
        g(this.b, elements, size);
        return size > 0;
    }

    @Override // kotlin.collections.AbstractC4921l
    public final Object b(int i) {
        j();
        C4913d c4913d = AbstractC4916g.a;
        int i2 = this.b;
        c4913d.getClass();
        C4913d.b(i, i2);
        return m(i);
    }

    @Override // java.util.AbstractList, java.util.AbstractCollection, java.util.Collection, java.util.List
    public final void clear() {
        j();
        n(0, this.b);
    }

    @Override // java.util.AbstractList, java.util.Collection, java.util.List
    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof List) {
            if (AbstractC3324c.b(this.a, 0, this.b, (List) obj)) {
                return true;
            }
        }
        return false;
    }

    public final void g(int i, Collection collection, int i2) {
        ((AbstractList) this).modCount++;
        k(i, i2);
        Iterator it2 = collection.iterator();
        for (int i3 = 0; i3 < i2; i3++) {
            this.a[i + i3] = it2.next();
        }
    }

    @Override // java.util.AbstractList, java.util.List
    public final Object get(int i) {
        C4913d c4913d = AbstractC4916g.a;
        int i2 = this.b;
        c4913d.getClass();
        C4913d.b(i, i2);
        return this.a[i];
    }

    public final void h(int i, Object obj) {
        ((AbstractList) this).modCount++;
        k(i, 1);
        this.a[i] = obj;
    }

    @Override // java.util.AbstractList, java.util.Collection, java.util.List
    public final int hashCode() {
        Object[] objArr = this.a;
        int i = this.b;
        int iHashCode = 1;
        for (int i2 = 0; i2 < i; i2++) {
            Object obj = objArr[i2];
            iHashCode = (iHashCode * 31) + (obj != null ? obj.hashCode() : 0);
        }
        return iHashCode;
    }

    @Override // java.util.AbstractList, java.util.List
    public final int indexOf(Object obj) {
        for (int i = 0; i < this.b; i++) {
            if (Intrinsics.b(this.a[i], obj)) {
                return i;
            }
        }
        return -1;
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.List
    public final boolean isEmpty() {
        return this.b == 0;
    }

    @Override // java.util.AbstractList, java.util.AbstractCollection, java.util.Collection, java.lang.Iterable, java.util.List
    public final Iterator iterator() {
        return listIterator(0);
    }

    public final void j() {
        if (this.c) {
            throw new UnsupportedOperationException();
        }
    }

    public final void k(int i, int i2) {
        int i3 = this.b + i2;
        if (i3 < 0) {
            throw new OutOfMemoryError();
        }
        Object[] objArr = this.a;
        if (i3 > objArr.length) {
            C4913d c4913d = AbstractC4916g.a;
            int length = objArr.length;
            c4913d.getClass();
            int iE = C4913d.e(length, i3);
            Object[] objArr2 = this.a;
            Intrinsics.checkNotNullParameter(objArr2, "<this>");
            Object[] objArrCopyOf = Arrays.copyOf(objArr2, iE);
            Intrinsics.checkNotNullExpressionValue(objArrCopyOf, "copyOf(...)");
            this.a = objArrCopyOf;
        }
        Object[] objArr3 = this.a;
        C4930v.h(objArr3, i + i2, objArr3, i, this.b);
        this.b += i2;
    }

    @Override // java.util.AbstractList, java.util.List
    public final int lastIndexOf(Object obj) {
        for (int i = this.b - 1; i >= 0; i--) {
            if (Intrinsics.b(this.a[i], obj)) {
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
        ((AbstractList) this).modCount++;
        Object[] objArr = this.a;
        Object obj = objArr[i];
        C4930v.h(objArr, i, objArr, i + 1, this.b);
        Object[] objArr2 = this.a;
        int i2 = this.b - 1;
        Intrinsics.checkNotNullParameter(objArr2, "<this>");
        objArr2[i2] = null;
        this.b--;
        return obj;
    }

    public final void n(int i, int i2) {
        if (i2 > 0) {
            ((AbstractList) this).modCount++;
        }
        Object[] objArr = this.a;
        C4930v.h(objArr, i, objArr, i + i2, this.b);
        Object[] objArr2 = this.a;
        int i3 = this.b;
        AbstractC3324c.g(i3 - i2, i3, objArr2);
        this.b -= i2;
    }

    public final int o(int i, int i2, Collection collection, boolean z) {
        int i3 = 0;
        int i4 = 0;
        while (i3 < i2) {
            int i5 = i + i3;
            if (collection.contains(this.a[i5]) == z) {
                Object[] objArr = this.a;
                i3++;
                objArr[i4 + i] = objArr[i5];
                i4++;
            } else {
                i3++;
            }
        }
        int i6 = i2 - i4;
        Object[] objArr2 = this.a;
        C4930v.h(objArr2, i + i4, objArr2, i2 + i, this.b);
        Object[] objArr3 = this.a;
        int i7 = this.b;
        AbstractC3324c.g(i7 - i6, i7, objArr3);
        if (i6 > 0) {
            ((AbstractList) this).modCount++;
        }
        this.b -= i6;
        return i6;
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.List
    public final boolean remove(Object obj) {
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
        j();
        return o(0, this.b, elements, false) > 0;
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.List
    public final boolean retainAll(Collection elements) {
        Intrinsics.checkNotNullParameter(elements, "elements");
        j();
        return o(0, this.b, elements, true) > 0;
    }

    @Override // java.util.AbstractList, java.util.List
    public final Object set(int i, Object obj) {
        j();
        C4913d c4913d = AbstractC4916g.a;
        int i2 = this.b;
        c4913d.getClass();
        C4913d.b(i, i2);
        Object[] objArr = this.a;
        Object obj2 = objArr[i];
        objArr[i] = obj;
        return obj2;
    }

    @Override // java.util.AbstractList, java.util.List
    public final List subList(int i, int i2) {
        C4913d c4913d = AbstractC4916g.a;
        int i3 = this.b;
        c4913d.getClass();
        C4913d.d(i, i2, i3);
        return new b(this.a, i, i2 - i, null, this);
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.List
    public final Object[] toArray(Object[] array) {
        Intrinsics.checkNotNullParameter(array, "array");
        int length = array.length;
        int i = this.b;
        if (length < i) {
            Object[] objArrCopyOfRange = Arrays.copyOfRange(this.a, 0, i, array.getClass());
            Intrinsics.checkNotNullExpressionValue(objArrCopyOfRange, "copyOfRange(...)");
            return objArrCopyOfRange;
        }
        C4930v.h(this.a, 0, array, 0, i);
        A.e(this.b, array);
        return array;
    }

    @Override // java.util.AbstractCollection
    public final String toString() {
        return AbstractC3324c.c(this.a, 0, this.b, this);
    }

    public /* synthetic */ d(int i, int i2, DefaultConstructorMarker defaultConstructorMarker) {
        this((i2 & 1) != 0 ? 10 : i);
    }

    @Override // java.util.AbstractList, java.util.List
    public final ListIterator listIterator(int i) {
        C4913d c4913d = AbstractC4916g.a;
        int i2 = this.b;
        c4913d.getClass();
        C4913d.c(i, i2);
        return new w(this, i);
    }

    public d(int i) {
        if (i >= 0) {
            this.a = new Object[i];
            return;
        }
        throw new IllegalArgumentException("capacity must be non-negative.");
    }

    @Override // java.util.AbstractList, java.util.List
    public final boolean addAll(int i, Collection elements) {
        Intrinsics.checkNotNullParameter(elements, "elements");
        j();
        C4913d c4913d = AbstractC4916g.a;
        int i2 = this.b;
        c4913d.getClass();
        C4913d.c(i, i2);
        int size = elements.size();
        g(i, elements, size);
        return size > 0;
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.List
    public final Object[] toArray() {
        return C4930v.n(0, this.b, this.a);
    }

    @Override // java.util.AbstractList, java.util.List
    public final void add(int i, Object obj) {
        j();
        C4913d c4913d = AbstractC4916g.a;
        int i2 = this.b;
        c4913d.getClass();
        C4913d.c(i, i2);
        ((AbstractList) this).modCount++;
        k(i, 1);
        this.a[i] = obj;
    }
}
