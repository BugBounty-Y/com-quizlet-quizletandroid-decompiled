package kotlin.collections;

import java.lang.reflect.Array;
import java.util.AbstractList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;
import java.util.NoSuchElementException;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* renamed from: kotlin.collections.s, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4927s extends AbstractC4921l {

    @NotNull
    public static final r d = new r(null);
    public static final Object[] e = new Object[0];
    public int a;
    public Object[] b;
    public int c;

    public C4927s() {
        this.b = e;
    }

    @Override // kotlin.collections.AbstractC4921l
    public final int a() {
        return this.c;
    }

    @Override // java.util.AbstractList, java.util.AbstractCollection, java.util.Collection, java.util.List
    public final boolean add(Object obj) {
        addLast(obj);
        return true;
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.List
    public final boolean addAll(Collection elements) {
        Intrinsics.checkNotNullParameter(elements, "elements");
        if (elements.isEmpty()) {
            return false;
        }
        s();
        g(elements.size() + a());
        e(o(a() + this.a), elements);
        return true;
    }

    public final void addFirst(Object obj) {
        s();
        g(this.c + 1);
        int i = this.a;
        int iE = i == 0 ? C4933y.E(this.b) : i - 1;
        this.a = iE;
        this.b[iE] = obj;
        this.c++;
    }

    public final void addLast(Object obj) {
        s();
        g(a() + 1);
        this.b[o(a() + this.a)] = obj;
        this.c = a() + 1;
    }

    @Override // kotlin.collections.AbstractC4921l
    public final Object b(int i) {
        C4913d c4913d = AbstractC4916g.a;
        int i2 = this.c;
        c4913d.getClass();
        C4913d.b(i, i2);
        if (i == B.i(this)) {
            return removeLast();
        }
        if (i == 0) {
            return removeFirst();
        }
        s();
        int iO = o(this.a + i);
        Object[] objArr = this.b;
        Object obj = objArr[iO];
        if (i < (this.c >> 1)) {
            int i3 = this.a;
            if (iO >= i3) {
                C4930v.h(objArr, i3 + 1, objArr, i3, iO);
            } else {
                C4930v.h(objArr, 1, objArr, 0, iO);
                Object[] objArr2 = this.b;
                objArr2[0] = objArr2[objArr2.length - 1];
                int i4 = this.a;
                C4930v.h(objArr2, i4 + 1, objArr2, i4, objArr2.length - 1);
            }
            Object[] objArr3 = this.b;
            int i5 = this.a;
            objArr3[i5] = null;
            this.a = j(i5);
        } else {
            int iO2 = o(B.i(this) + this.a);
            if (iO <= iO2) {
                Object[] objArr4 = this.b;
                C4930v.h(objArr4, iO, objArr4, iO + 1, iO2 + 1);
            } else {
                Object[] objArr5 = this.b;
                C4930v.h(objArr5, iO, objArr5, iO + 1, objArr5.length);
                Object[] objArr6 = this.b;
                objArr6[objArr6.length - 1] = objArr6[0];
                C4930v.h(objArr6, 0, objArr6, 1, iO2 + 1);
            }
            this.b[iO2] = null;
        }
        this.c--;
        return obj;
    }

    @Override // java.util.AbstractList, java.util.AbstractCollection, java.util.Collection, java.util.List
    public final void clear() {
        if (!isEmpty()) {
            s();
            n(this.a, o(a() + this.a));
        }
        this.a = 0;
        this.c = 0;
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.List
    public final boolean contains(Object obj) {
        return indexOf(obj) != -1;
    }

    public final void e(int i, Collection collection) {
        Iterator it2 = collection.iterator();
        int length = this.b.length;
        while (i < length && it2.hasNext()) {
            this.b[i] = it2.next();
            i++;
        }
        int i2 = this.a;
        for (int i3 = 0; i3 < i2 && it2.hasNext(); i3++) {
            this.b[i3] = it2.next();
        }
        this.c = collection.size() + this.c;
    }

    public final Object first() {
        if (isEmpty()) {
            throw new NoSuchElementException("ArrayDeque is empty.");
        }
        return this.b[this.a];
    }

    public final void g(int i) {
        if (i < 0) {
            throw new IllegalStateException("Deque is too big.");
        }
        Object[] objArr = this.b;
        if (i <= objArr.length) {
            return;
        }
        if (objArr == e) {
            if (i < 10) {
                i = 10;
            }
            this.b = new Object[i];
            return;
        }
        C4913d c4913d = AbstractC4916g.a;
        int length = objArr.length;
        c4913d.getClass();
        Object[] objArr2 = new Object[C4913d.e(length, i)];
        Object[] objArr3 = this.b;
        C4930v.h(objArr3, 0, objArr2, this.a, objArr3.length);
        Object[] objArr4 = this.b;
        int length2 = objArr4.length;
        int i2 = this.a;
        C4930v.h(objArr4, length2 - i2, objArr2, 0, i2);
        this.a = 0;
        this.b = objArr2;
    }

    @Override // java.util.AbstractList, java.util.List
    public final Object get(int i) {
        C4913d c4913d = AbstractC4916g.a;
        int i2 = this.c;
        c4913d.getClass();
        C4913d.b(i, i2);
        return this.b[o(this.a + i)];
    }

    public final Object h() {
        if (isEmpty()) {
            return null;
        }
        return this.b[this.a];
    }

    @Override // java.util.AbstractList, java.util.List
    public final int indexOf(Object obj) {
        int i;
        int iO = o(a() + this.a);
        int length = this.a;
        if (length < iO) {
            while (length < iO) {
                if (Intrinsics.b(obj, this.b[length])) {
                    i = this.a;
                } else {
                    length++;
                }
            }
            return -1;
        }
        if (length < iO) {
            return -1;
        }
        int length2 = this.b.length;
        while (true) {
            if (length >= length2) {
                for (int i2 = 0; i2 < iO; i2++) {
                    if (Intrinsics.b(obj, this.b[i2])) {
                        length = i2 + this.b.length;
                        i = this.a;
                    }
                }
                return -1;
            }
            if (Intrinsics.b(obj, this.b[length])) {
                i = this.a;
                break;
            }
            length++;
        }
        return length - i;
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.List
    public final boolean isEmpty() {
        return a() == 0;
    }

    public final int j(int i) {
        if (i == C4933y.E(this.b)) {
            return 0;
        }
        return i + 1;
    }

    public final Object k() {
        if (isEmpty()) {
            return null;
        }
        return this.b[o(B.i(this) + this.a)];
    }

    public final Object last() {
        if (isEmpty()) {
            throw new NoSuchElementException("ArrayDeque is empty.");
        }
        return this.b[o(B.i(this) + this.a)];
    }

    @Override // java.util.AbstractList, java.util.List
    public final int lastIndexOf(Object obj) {
        int iE;
        int i;
        int iO = o(a() + this.a);
        int i2 = this.a;
        if (i2 < iO) {
            iE = iO - 1;
            if (i2 <= iE) {
                while (!Intrinsics.b(obj, this.b[iE])) {
                    if (iE != i2) {
                        iE--;
                    }
                }
                i = this.a;
                return iE - i;
            }
            return -1;
        }
        if (i2 > iO) {
            int i3 = iO - 1;
            while (true) {
                if (-1 >= i3) {
                    iE = C4933y.E(this.b);
                    int i4 = this.a;
                    if (i4 <= iE) {
                        while (!Intrinsics.b(obj, this.b[iE])) {
                            if (iE != i4) {
                                iE--;
                            }
                        }
                        i = this.a;
                    }
                } else {
                    if (Intrinsics.b(obj, this.b[i3])) {
                        iE = i3 + this.b.length;
                        i = this.a;
                        break;
                    }
                    i3--;
                }
            }
        }
        return -1;
    }

    public final int m(int i) {
        return i < 0 ? i + this.b.length : i;
    }

    public final void n(int i, int i2) {
        if (i < i2) {
            C4930v.o(this.b, null, i, i2);
            return;
        }
        Object[] objArr = this.b;
        int length = objArr.length;
        Intrinsics.checkNotNullParameter(objArr, "<this>");
        Arrays.fill(objArr, i, length, (Object) null);
        C4930v.o(this.b, null, 0, i2);
    }

    public final int o(int i) {
        Object[] objArr = this.b;
        return i >= objArr.length ? i - objArr.length : i;
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.List
    public final boolean remove(Object obj) {
        int iIndexOf = indexOf(obj);
        if (iIndexOf == -1) {
            return false;
        }
        b(iIndexOf);
        return true;
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.List
    public final boolean removeAll(Collection elements) {
        int iO;
        Intrinsics.checkNotNullParameter(elements, "elements");
        boolean z = false;
        z = false;
        z = false;
        if (!isEmpty() && this.b.length != 0) {
            int iO2 = o(this.c + this.a);
            int i = this.a;
            if (i < iO2) {
                iO = i;
                while (i < iO2) {
                    Object obj = this.b[i];
                    if (elements.contains(obj)) {
                        z = true;
                    } else {
                        this.b[iO] = obj;
                        iO++;
                    }
                    i++;
                }
                C4930v.o(this.b, null, iO, iO2);
            } else {
                int length = this.b.length;
                boolean z2 = false;
                int i2 = i;
                while (i < length) {
                    Object[] objArr = this.b;
                    Object obj2 = objArr[i];
                    objArr[i] = null;
                    if (elements.contains(obj2)) {
                        z2 = true;
                    } else {
                        this.b[i2] = obj2;
                        i2++;
                    }
                    i++;
                }
                iO = o(i2);
                for (int i3 = 0; i3 < iO2; i3++) {
                    Object[] objArr2 = this.b;
                    Object obj3 = objArr2[i3];
                    objArr2[i3] = null;
                    if (elements.contains(obj3)) {
                        z2 = true;
                    } else {
                        this.b[iO] = obj3;
                        iO = j(iO);
                    }
                }
                z = z2;
            }
            if (z) {
                s();
                this.c = m(iO - this.a);
            }
        }
        return z;
    }

    public final Object removeFirst() {
        if (isEmpty()) {
            throw new NoSuchElementException("ArrayDeque is empty.");
        }
        s();
        Object[] objArr = this.b;
        int i = this.a;
        Object obj = objArr[i];
        objArr[i] = null;
        this.a = j(i);
        this.c = a() - 1;
        return obj;
    }

    public final Object removeLast() {
        if (isEmpty()) {
            throw new NoSuchElementException("ArrayDeque is empty.");
        }
        s();
        int iO = o(B.i(this) + this.a);
        Object[] objArr = this.b;
        Object obj = objArr[iO];
        objArr[iO] = null;
        this.c = a() - 1;
        return obj;
    }

    @Override // java.util.AbstractList
    public final void removeRange(int i, int i2) {
        C4913d c4913d = AbstractC4916g.a;
        int i3 = this.c;
        c4913d.getClass();
        C4913d.d(i, i2, i3);
        int i4 = i2 - i;
        if (i4 == 0) {
            return;
        }
        if (i4 == this.c) {
            clear();
            return;
        }
        if (i4 == 1) {
            b(i);
            return;
        }
        s();
        if (i < this.c - i2) {
            int iO = o((i - 1) + this.a);
            int iO2 = o((i2 - 1) + this.a);
            while (i > 0) {
                int i5 = iO + 1;
                int iMin = Math.min(i, Math.min(i5, iO2 + 1));
                Object[] objArr = this.b;
                int i6 = iO2 - iMin;
                int i7 = iO - iMin;
                C4930v.h(objArr, i6 + 1, objArr, i7 + 1, i5);
                iO = m(i7);
                iO2 = m(i6);
                i -= iMin;
            }
            int iO3 = o(this.a + i4);
            n(this.a, iO3);
            this.a = iO3;
        } else {
            int iO4 = o(this.a + i2);
            int iO5 = o(this.a + i);
            int i8 = this.c;
            while (true) {
                i8 -= i2;
                if (i8 <= 0) {
                    break;
                }
                Object[] objArr2 = this.b;
                i2 = Math.min(i8, Math.min(objArr2.length - iO4, objArr2.length - iO5));
                Object[] objArr3 = this.b;
                int i9 = iO4 + i2;
                C4930v.h(objArr3, iO5, objArr3, iO4, i9);
                iO4 = o(i9);
                iO5 = o(iO5 + i2);
            }
            int iO6 = o(this.c + this.a);
            n(m(iO6 - i4), iO6);
        }
        this.c -= i4;
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.List
    public final boolean retainAll(Collection elements) {
        int iO;
        Intrinsics.checkNotNullParameter(elements, "elements");
        boolean z = false;
        z = false;
        z = false;
        if (!isEmpty() && this.b.length != 0) {
            int iO2 = o(this.c + this.a);
            int i = this.a;
            if (i < iO2) {
                iO = i;
                while (i < iO2) {
                    Object obj = this.b[i];
                    if (elements.contains(obj)) {
                        this.b[iO] = obj;
                        iO++;
                    } else {
                        z = true;
                    }
                    i++;
                }
                C4930v.o(this.b, null, iO, iO2);
            } else {
                int length = this.b.length;
                boolean z2 = false;
                int i2 = i;
                while (i < length) {
                    Object[] objArr = this.b;
                    Object obj2 = objArr[i];
                    objArr[i] = null;
                    if (elements.contains(obj2)) {
                        this.b[i2] = obj2;
                        i2++;
                    } else {
                        z2 = true;
                    }
                    i++;
                }
                iO = o(i2);
                for (int i3 = 0; i3 < iO2; i3++) {
                    Object[] objArr2 = this.b;
                    Object obj3 = objArr2[i3];
                    objArr2[i3] = null;
                    if (elements.contains(obj3)) {
                        this.b[iO] = obj3;
                        iO = j(iO);
                    } else {
                        z2 = true;
                    }
                }
                z = z2;
            }
            if (z) {
                s();
                this.c = m(iO - this.a);
            }
        }
        return z;
    }

    public final void s() {
        ((AbstractList) this).modCount++;
    }

    @Override // java.util.AbstractList, java.util.List
    public final Object set(int i, Object obj) {
        C4913d c4913d = AbstractC4916g.a;
        int i2 = this.c;
        c4913d.getClass();
        C4913d.b(i, i2);
        int iO = o(this.a + i);
        Object[] objArr = this.b;
        Object obj2 = objArr[iO];
        objArr[iO] = obj;
        return obj2;
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.List
    public final Object[] toArray() {
        return toArray(new Object[a()]);
    }

    @Override // java.util.AbstractList, java.util.List
    public final void add(int i, Object obj) {
        C4913d c4913d = AbstractC4916g.a;
        int i2 = this.c;
        c4913d.getClass();
        C4913d.c(i, i2);
        if (i == this.c) {
            addLast(obj);
            return;
        }
        if (i == 0) {
            addFirst(obj);
            return;
        }
        s();
        g(this.c + 1);
        int iO = o(this.a + i);
        int i3 = this.c;
        if (i < ((i3 + 1) >> 1)) {
            int iE = iO == 0 ? C4933y.E(this.b) : iO - 1;
            int i4 = this.a;
            int iE2 = i4 == 0 ? C4933y.E(this.b) : i4 - 1;
            int i5 = this.a;
            if (iE >= i5) {
                Object[] objArr = this.b;
                objArr[iE2] = objArr[i5];
                C4930v.h(objArr, i5, objArr, i5 + 1, iE + 1);
            } else {
                Object[] objArr2 = this.b;
                C4930v.h(objArr2, i5 - 1, objArr2, i5, objArr2.length);
                Object[] objArr3 = this.b;
                objArr3[objArr3.length - 1] = objArr3[0];
                C4930v.h(objArr3, 0, objArr3, 1, iE + 1);
            }
            this.b[iE] = obj;
            this.a = iE2;
        } else {
            int iO2 = o(i3 + this.a);
            if (iO < iO2) {
                Object[] objArr4 = this.b;
                C4930v.h(objArr4, iO + 1, objArr4, iO, iO2);
            } else {
                Object[] objArr5 = this.b;
                C4930v.h(objArr5, 1, objArr5, 0, iO2);
                Object[] objArr6 = this.b;
                objArr6[0] = objArr6[objArr6.length - 1];
                C4930v.h(objArr6, iO + 1, objArr6, iO, objArr6.length - 1);
            }
            this.b[iO] = obj;
        }
        this.c++;
    }

    public C4927s(int i) {
        Object[] objArr;
        if (i == 0) {
            objArr = e;
        } else if (i > 0) {
            objArr = new Object[i];
        } else {
            throw new IllegalArgumentException(android.support.v4.media.session.a.f(i, "Illegal Capacity: "));
        }
        this.b = objArr;
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.List
    public final Object[] toArray(Object[] reference) throws NegativeArraySizeException {
        Intrinsics.checkNotNullParameter(reference, "array");
        int length = reference.length;
        int i = this.c;
        if (length < i) {
            Intrinsics.checkNotNullParameter(reference, "reference");
            Object objNewInstance = Array.newInstance(reference.getClass().getComponentType(), i);
            Intrinsics.e(objNewInstance, "null cannot be cast to non-null type kotlin.Array<T of kotlin.collections.ArraysKt__ArraysJVMKt.arrayOfNulls>");
            reference = (Object[]) objNewInstance;
        }
        int iO = o(this.c + this.a);
        int i2 = this.a;
        if (i2 < iO) {
            C4930v.j(this.b, i2, reference, iO, 2);
        } else if (!isEmpty()) {
            Object[] objArr = this.b;
            C4930v.h(objArr, 0, reference, this.a, objArr.length);
            Object[] objArr2 = this.b;
            C4930v.h(objArr2, objArr2.length - this.a, reference, 0, iO);
        }
        A.e(this.c, reference);
        return reference;
    }

    @Override // java.util.AbstractList, java.util.List
    public final boolean addAll(int i, Collection elements) {
        Intrinsics.checkNotNullParameter(elements, "elements");
        C4913d c4913d = AbstractC4916g.a;
        int i2 = this.c;
        c4913d.getClass();
        C4913d.c(i, i2);
        if (elements.isEmpty()) {
            return false;
        }
        if (i == this.c) {
            return addAll(elements);
        }
        s();
        g(elements.size() + this.c);
        int iO = o(this.c + this.a);
        int iO2 = o(this.a + i);
        int size = elements.size();
        if (i < ((this.c + 1) >> 1)) {
            int i3 = this.a;
            int length = i3 - size;
            if (iO2 < i3) {
                Object[] objArr = this.b;
                C4930v.h(objArr, length, objArr, i3, objArr.length);
                if (size >= iO2) {
                    Object[] objArr2 = this.b;
                    C4930v.h(objArr2, objArr2.length - size, objArr2, 0, iO2);
                } else {
                    Object[] objArr3 = this.b;
                    C4930v.h(objArr3, objArr3.length - size, objArr3, 0, size);
                    Object[] objArr4 = this.b;
                    C4930v.h(objArr4, 0, objArr4, size, iO2);
                }
            } else if (length >= 0) {
                Object[] objArr5 = this.b;
                C4930v.h(objArr5, length, objArr5, i3, iO2);
            } else {
                Object[] objArr6 = this.b;
                length += objArr6.length;
                int i4 = iO2 - i3;
                int length2 = objArr6.length - length;
                if (length2 >= i4) {
                    C4930v.h(objArr6, length, objArr6, i3, iO2);
                } else {
                    C4930v.h(objArr6, length, objArr6, i3, i3 + length2);
                    Object[] objArr7 = this.b;
                    C4930v.h(objArr7, 0, objArr7, this.a + length2, iO2);
                }
            }
            this.a = length;
            e(m(iO2 - size), elements);
            return true;
        }
        int i5 = iO2 + size;
        if (iO2 < iO) {
            int i6 = size + iO;
            Object[] objArr8 = this.b;
            if (i6 <= objArr8.length) {
                C4930v.h(objArr8, i5, objArr8, iO2, iO);
            } else if (i5 >= objArr8.length) {
                C4930v.h(objArr8, i5 - objArr8.length, objArr8, iO2, iO);
            } else {
                int length3 = iO - (i6 - objArr8.length);
                C4930v.h(objArr8, 0, objArr8, length3, iO);
                Object[] objArr9 = this.b;
                C4930v.h(objArr9, i5, objArr9, iO2, length3);
            }
        } else {
            Object[] objArr10 = this.b;
            C4930v.h(objArr10, size, objArr10, 0, iO);
            Object[] objArr11 = this.b;
            if (i5 >= objArr11.length) {
                C4930v.h(objArr11, i5 - objArr11.length, objArr11, iO2, objArr11.length);
            } else {
                C4930v.h(objArr11, 0, objArr11, objArr11.length - size, objArr11.length);
                Object[] objArr12 = this.b;
                C4930v.h(objArr12, i5, objArr12, iO2, objArr12.length - size);
            }
        }
        e(iO2, elements);
        return true;
    }

    public C4927s(Collection elements) {
        Intrinsics.checkNotNullParameter(elements, "elements");
        Object[] array = elements.toArray(new Object[0]);
        this.b = array;
        this.c = array.length;
        if (array.length == 0) {
            this.b = e;
        }
    }
}
