package androidx.collection;

import java.lang.reflect.Array;
import java.util.Collection;
import java.util.ConcurrentModificationException;
import java.util.Iterator;
import java.util.Set;
import kotlin.collections.C4930v;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.collection.g, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0209g implements Collection, Set, kotlin.jvm.internal.markers.b, kotlin.jvm.internal.markers.f {
    public int[] a = androidx.collection.internal.a.a;
    public Object[] b = androidx.collection.internal.a.c;
    public int c;

    public C0209g(int i) {
        if (i > 0) {
            r.b(this, i);
        }
    }

    public final Object a(int i) {
        int i2 = this.c;
        Object[] objArr = this.b;
        Object obj = objArr[i];
        if (i2 <= 1) {
            clear();
            return obj;
        }
        int i3 = i2 - 1;
        int[] iArr = this.a;
        if (iArr.length <= 8 || i2 >= iArr.length / 3) {
            if (i < i3) {
                int i4 = i + 1;
                C4930v.e(i, i4, i2, iArr, iArr);
                Object[] objArr2 = this.b;
                C4930v.h(objArr2, i, objArr2, i4, i2);
            }
            this.b[i3] = null;
        } else {
            r.b(this, i2 > 8 ? i2 + (i2 >> 1) : 8);
            if (i > 0) {
                C4930v.i(0, i, 6, iArr, this.a);
                C4930v.j(objArr, 0, this.b, i, 6);
            }
            if (i < i3) {
                int i5 = i + 1;
                C4930v.e(i, i5, i2, iArr, this.a);
                C4930v.h(objArr, i, this.b, i5, i2);
            }
        }
        if (i2 != this.c) {
            throw new ConcurrentModificationException();
        }
        this.c = i3;
        return obj;
    }

    @Override // java.util.Collection, java.util.Set
    public final boolean add(Object obj) {
        int i;
        int iC;
        int i2 = this.c;
        if (obj == null) {
            Intrinsics.checkNotNullParameter(this, "<this>");
            iC = r.c(this, null, 0);
            i = 0;
        } else {
            int iHashCode = obj.hashCode();
            i = iHashCode;
            iC = r.c(this, obj, iHashCode);
        }
        if (iC >= 0) {
            return false;
        }
        int i3 = ~iC;
        int[] iArr = this.a;
        if (i2 >= iArr.length) {
            int i4 = 8;
            if (i2 >= 8) {
                i4 = (i2 >> 1) + i2;
            } else if (i2 < 4) {
                i4 = 4;
            }
            Object[] objArr = this.b;
            r.b(this, i4);
            if (i2 != this.c) {
                throw new ConcurrentModificationException();
            }
            int[] iArr2 = this.a;
            if (iArr2.length != 0) {
                C4930v.i(0, iArr.length, 6, iArr, iArr2);
                C4930v.j(objArr, 0, this.b, objArr.length, 6);
            }
        }
        if (i3 < i2) {
            int[] iArr3 = this.a;
            int i5 = i3 + 1;
            C4930v.e(i5, i3, i2, iArr3, iArr3);
            Object[] objArr2 = this.b;
            C4930v.h(objArr2, i5, objArr2, i3, i2);
        }
        int i6 = this.c;
        if (i2 == i6) {
            int[] iArr4 = this.a;
            if (i3 < iArr4.length) {
                iArr4[i3] = i;
                this.b[i3] = obj;
                this.c = i6 + 1;
                return true;
            }
        }
        throw new ConcurrentModificationException();
    }

    @Override // java.util.Collection, java.util.Set
    public final boolean addAll(Collection elements) {
        Intrinsics.checkNotNullParameter(elements, "elements");
        int size = elements.size() + this.c;
        int i = this.c;
        int[] iArr = this.a;
        boolean zAdd = false;
        if (iArr.length < size) {
            Object[] objArr = this.b;
            r.b(this, size);
            int i2 = this.c;
            if (i2 > 0) {
                C4930v.i(0, i2, 6, iArr, this.a);
                C4930v.j(objArr, 0, this.b, this.c, 6);
            }
        }
        if (this.c != i) {
            throw new ConcurrentModificationException();
        }
        Iterator it2 = elements.iterator();
        while (it2.hasNext()) {
            zAdd |= add(it2.next());
        }
        return zAdd;
    }

    @Override // java.util.Collection, java.util.Set
    public final void clear() {
        if (this.c != 0) {
            int[] iArr = androidx.collection.internal.a.a;
            Intrinsics.checkNotNullParameter(iArr, "<set-?>");
            this.a = iArr;
            Object[] objArr = androidx.collection.internal.a.c;
            Intrinsics.checkNotNullParameter(objArr, "<set-?>");
            this.b = objArr;
            this.c = 0;
        }
        if (this.c != 0) {
            throw new ConcurrentModificationException();
        }
    }

    @Override // java.util.Collection, java.util.Set
    public final boolean contains(Object obj) {
        int iC;
        if (obj == null) {
            Intrinsics.checkNotNullParameter(this, "<this>");
            iC = r.c(this, null, 0);
        } else {
            iC = r.c(this, obj, obj.hashCode());
        }
        return iC >= 0;
    }

    @Override // java.util.Collection, java.util.Set
    public final boolean containsAll(Collection elements) {
        Intrinsics.checkNotNullParameter(elements, "elements");
        Iterator it2 = elements.iterator();
        while (it2.hasNext()) {
            if (!contains(it2.next())) {
                return false;
            }
        }
        return true;
    }

    @Override // java.util.Collection, java.util.Set
    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof Set) || this.c != ((Set) obj).size()) {
            return false;
        }
        try {
            int i = this.c;
            for (int i2 = 0; i2 < i; i2++) {
                if (!((Set) obj).contains(this.b[i2])) {
                    return false;
                }
            }
            return true;
        } catch (ClassCastException | NullPointerException unused) {
            return false;
        }
    }

    @Override // java.util.Collection, java.util.Set
    public final int hashCode() {
        int[] iArr = this.a;
        int i = this.c;
        int i2 = 0;
        for (int i3 = 0; i3 < i; i3++) {
            i2 += iArr[i3];
        }
        return i2;
    }

    @Override // java.util.Collection, java.util.Set
    public final boolean isEmpty() {
        return this.c <= 0;
    }

    @Override // java.util.Collection, java.lang.Iterable, java.util.Set
    public final Iterator iterator() {
        return new C0204b(this);
    }

    @Override // java.util.Collection, java.util.Set
    public final boolean remove(Object obj) {
        int iC;
        if (obj == null) {
            Intrinsics.checkNotNullParameter(this, "<this>");
            iC = r.c(this, null, 0);
        } else {
            iC = r.c(this, obj, obj.hashCode());
        }
        if (iC < 0) {
            return false;
        }
        a(iC);
        return true;
    }

    @Override // java.util.Collection, java.util.Set
    public final boolean removeAll(Collection elements) {
        Intrinsics.checkNotNullParameter(elements, "elements");
        Iterator it2 = elements.iterator();
        boolean zRemove = false;
        while (it2.hasNext()) {
            zRemove |= remove(it2.next());
        }
        return zRemove;
    }

    @Override // java.util.Collection, java.util.Set
    public final boolean retainAll(Collection elements) {
        Intrinsics.checkNotNullParameter(elements, "elements");
        boolean z = false;
        for (int i = this.c - 1; -1 < i; i--) {
            if (!CollectionsKt.F(elements, this.b[i])) {
                a(i);
                z = true;
            }
        }
        return z;
    }

    @Override // java.util.Collection, java.util.Set
    public final int size() {
        return this.c;
    }

    @Override // java.util.Collection, java.util.Set
    public final Object[] toArray() {
        return C4930v.n(0, this.c, this.b);
    }

    public final String toString() {
        if (isEmpty()) {
            return "{}";
        }
        StringBuilder sb = new StringBuilder(this.c * 14);
        sb.append('{');
        int i = this.c;
        for (int i2 = 0; i2 < i; i2++) {
            if (i2 > 0) {
                sb.append(", ");
            }
            Object obj = this.b[i2];
            if (obj != this) {
                sb.append(obj);
            } else {
                sb.append("(this Set)");
            }
        }
        sb.append('}');
        String string = sb.toString();
        Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
        return string;
    }

    @Override // java.util.Collection, java.util.Set
    public final Object[] toArray(Object[] array) {
        Intrinsics.checkNotNullParameter(array, "array");
        int i = this.c;
        if (array.length < i) {
            array = (Object[]) Array.newInstance(array.getClass().getComponentType(), i);
        } else if (array.length > i) {
            array[i] = null;
        }
        C4930v.h(this.b, 0, array, 0, this.c);
        Intrinsics.d(array);
        return array;
    }
}
