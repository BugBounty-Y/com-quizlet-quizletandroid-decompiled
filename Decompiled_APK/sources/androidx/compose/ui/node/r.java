package androidx.compose.ui.node;

import com.skydoves.balloon.internals.DefinitionKt;
import java.util.Arrays;
import java.util.Collection;
import java.util.Comparator;
import java.util.Iterator;
import java.util.List;
import java.util.ListIterator;
import java.util.function.UnaryOperator;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.AbstractC4958q;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class r implements List, kotlin.jvm.internal.markers.a {
    public int d;
    public Object[] a = new Object[16];
    public long[] b = new long[16];
    public int c = -1;
    public boolean e = true;

    public final long a() {
        long jA = AbstractC0910f.a(Float.POSITIVE_INFINITY, false);
        int i = this.c + 1;
        int i2 = kotlin.collections.B.i(this);
        if (i <= i2) {
            while (true) {
                long j = this.b[i];
                if (AbstractC0910f.h(j, jA) < 0) {
                    jA = j;
                }
                if (Float.intBitsToFloat((int) (jA >> 32)) < DefinitionKt.NO_Float_VALUE && ((int) (4294967295L & jA)) != 0) {
                    return jA;
                }
                if (i == i2) {
                    break;
                }
                i++;
            }
        }
        return jA;
    }

    @Override // java.util.List
    public final /* bridge */ /* synthetic */ void add(int i, Object obj) {
        throw new UnsupportedOperationException("Operation is not supported for read-only collection");
    }

    @Override // java.util.List
    public final boolean addAll(int i, Collection collection) {
        throw new UnsupportedOperationException("Operation is not supported for read-only collection");
    }

    public final void b(androidx.compose.ui.p pVar, float f, boolean z, Function0 function0) {
        int i = this.c;
        int i2 = i + 1;
        this.c = i2;
        Object[] objArr = this.a;
        if (i2 >= objArr.length) {
            int length = objArr.length + 16;
            Object[] objArrCopyOf = Arrays.copyOf(objArr, length);
            Intrinsics.checkNotNullExpressionValue(objArrCopyOf, "copyOf(this, newSize)");
            this.a = objArrCopyOf;
            long[] jArrCopyOf = Arrays.copyOf(this.b, length);
            Intrinsics.checkNotNullExpressionValue(jArrCopyOf, "copyOf(this, newSize)");
            this.b = jArrCopyOf;
        }
        Object[] objArr2 = this.a;
        int i3 = this.c;
        objArr2[i3] = pVar;
        this.b[i3] = AbstractC0910f.a(f, z);
        e();
        function0.invoke();
        this.c = i;
    }

    @Override // java.util.List, java.util.Collection
    public final void clear() {
        this.c = -1;
        e();
        this.e = true;
    }

    @Override // java.util.List, java.util.Collection
    public final boolean contains(Object obj) {
        return (obj instanceof androidx.compose.ui.p) && indexOf((androidx.compose.ui.p) obj) != -1;
    }

    @Override // java.util.List, java.util.Collection
    public final boolean containsAll(Collection collection) {
        Iterator it2 = collection.iterator();
        while (it2.hasNext()) {
            if (!contains((androidx.compose.ui.p) it2.next())) {
                return false;
            }
        }
        return true;
    }

    public final void e() {
        int i = this.c + 1;
        int i2 = kotlin.collections.B.i(this);
        if (i <= i2) {
            while (true) {
                this.a[i] = null;
                if (i == i2) {
                    break;
                } else {
                    i++;
                }
            }
        }
        this.d = this.c + 1;
    }

    @Override // java.util.List
    public final Object get(int i) {
        Object obj = this.a[i];
        Intrinsics.e(obj, "null cannot be cast to non-null type androidx.compose.ui.Modifier.Node");
        return (androidx.compose.ui.p) obj;
    }

    @Override // java.util.List
    public final int indexOf(Object obj) {
        if (!(obj instanceof androidx.compose.ui.p)) {
            return -1;
        }
        androidx.compose.ui.p pVar = (androidx.compose.ui.p) obj;
        int i = kotlin.collections.B.i(this);
        if (i >= 0) {
            int i2 = 0;
            while (!Intrinsics.b(this.a[i2], pVar)) {
                if (i2 != i) {
                    i2++;
                }
            }
            return i2;
        }
        return -1;
    }

    @Override // java.util.List, java.util.Collection
    public final boolean isEmpty() {
        return this.d == 0;
    }

    @Override // java.util.List, java.util.Collection, java.lang.Iterable
    public final Iterator iterator() {
        return new androidx.compose.runtime.snapshots.w(this, 0, 7);
    }

    @Override // java.util.List
    public final int lastIndexOf(Object obj) {
        if (!(obj instanceof androidx.compose.ui.p)) {
            return -1;
        }
        androidx.compose.ui.p pVar = (androidx.compose.ui.p) obj;
        for (int i = kotlin.collections.B.i(this); -1 < i; i--) {
            if (Intrinsics.b(this.a[i], pVar)) {
                return i;
            }
        }
        return -1;
    }

    @Override // java.util.List
    public final ListIterator listIterator() {
        return new androidx.compose.runtime.snapshots.w(this, 0, 7);
    }

    @Override // java.util.List
    public final /* bridge */ /* synthetic */ Object remove(int i) {
        throw new UnsupportedOperationException("Operation is not supported for read-only collection");
    }

    @Override // java.util.List, java.util.Collection
    public final boolean removeAll(Collection collection) {
        throw new UnsupportedOperationException("Operation is not supported for read-only collection");
    }

    @Override // java.util.List
    public final void replaceAll(UnaryOperator unaryOperator) {
        throw new UnsupportedOperationException("Operation is not supported for read-only collection");
    }

    @Override // java.util.List, java.util.Collection
    public final boolean retainAll(Collection collection) {
        throw new UnsupportedOperationException("Operation is not supported for read-only collection");
    }

    @Override // java.util.List
    public final /* bridge */ /* synthetic */ Object set(int i, Object obj) {
        throw new UnsupportedOperationException("Operation is not supported for read-only collection");
    }

    @Override // java.util.List, java.util.Collection
    public final int size() {
        return this.d;
    }

    @Override // java.util.List
    public final void sort(Comparator comparator) {
        throw new UnsupportedOperationException("Operation is not supported for read-only collection");
    }

    @Override // java.util.List
    public final List subList(int i, int i2) {
        return new C0921q(this, i, i2);
    }

    @Override // java.util.List, java.util.Collection
    public final Object[] toArray() {
        return AbstractC4958q.a(this);
    }

    @Override // java.util.List, java.util.Collection
    public final /* bridge */ /* synthetic */ boolean add(Object obj) {
        throw new UnsupportedOperationException("Operation is not supported for read-only collection");
    }

    @Override // java.util.List, java.util.Collection
    public final boolean addAll(Collection collection) {
        throw new UnsupportedOperationException("Operation is not supported for read-only collection");
    }

    @Override // java.util.List
    public final ListIterator listIterator(int i) {
        return new androidx.compose.runtime.snapshots.w(this, i, 6);
    }

    @Override // java.util.List, java.util.Collection
    public final boolean remove(Object obj) {
        throw new UnsupportedOperationException("Operation is not supported for read-only collection");
    }

    @Override // java.util.List, java.util.Collection
    public final Object[] toArray(Object[] objArr) {
        return AbstractC4958q.b(this, objArr);
    }
}
