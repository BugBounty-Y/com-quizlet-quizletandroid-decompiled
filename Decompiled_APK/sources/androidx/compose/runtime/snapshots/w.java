package androidx.compose.runtime.snapshots;

import java.util.AbstractList;
import java.util.ConcurrentModificationException;
import java.util.ListIterator;
import java.util.NoSuchElementException;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class w implements ListIterator, kotlin.jvm.internal.markers.a {
    public final /* synthetic */ int a;
    public int b;
    public int c;
    public int d;
    public final Object e;

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public w(androidx.compose.ui.node.r rVar, int i, int i2) {
        this(rVar, (i2 & 1) != 0 ? 0 : i, 0, rVar.d);
        this.a = 1;
    }

    public void a() {
        if (((AbstractList) ((kotlin.collections.builders.b) this.e).e).modCount != this.d) {
            throw new ConcurrentModificationException();
        }
    }

    @Override // java.util.ListIterator
    public final void add(Object obj) {
        switch (this.a) {
            case 0:
                d();
                int i = this.b + 1;
                q qVar = (q) this.e;
                qVar.add(i, obj);
                this.c = -1;
                this.b++;
                this.d = qVar.i();
                return;
            case 1:
                throw new UnsupportedOperationException("Operation is not supported for read-only collection");
            case 2:
                a();
                int i2 = this.b;
                this.b = i2 + 1;
                kotlin.collections.builders.b bVar = (kotlin.collections.builders.b) this.e;
                bVar.add(i2, obj);
                this.c = -1;
                this.d = ((AbstractList) bVar).modCount;
                return;
            default:
                b();
                int i3 = this.b;
                this.b = i3 + 1;
                kotlin.collections.builders.d dVar = (kotlin.collections.builders.d) this.e;
                dVar.add(i3, obj);
                this.c = -1;
                this.d = ((AbstractList) dVar).modCount;
                return;
        }
    }

    public void b() {
        if (((AbstractList) ((kotlin.collections.builders.d) this.e)).modCount != this.d) {
            throw new ConcurrentModificationException();
        }
    }

    public void d() {
        if (((q) this.e).i() != this.d) {
            throw new ConcurrentModificationException();
        }
    }

    @Override // java.util.ListIterator, java.util.Iterator
    public final boolean hasNext() {
        switch (this.a) {
            case 0:
                return this.b < ((q) this.e).size() - 1;
            case 1:
                return this.b < this.d;
            case 2:
                return this.b < ((kotlin.collections.builders.b) this.e).c;
            default:
                return this.b < ((kotlin.collections.builders.d) this.e).b;
        }
    }

    @Override // java.util.ListIterator
    public final boolean hasPrevious() {
        switch (this.a) {
            case 0:
                if (this.b >= 0) {
                }
                break;
            case 1:
                if (this.b > this.c) {
                }
                break;
            case 2:
                if (this.b > 0) {
                }
                break;
            default:
                if (this.b > 0) {
                }
                break;
        }
        return false;
    }

    @Override // java.util.ListIterator, java.util.Iterator
    public final Object next() {
        switch (this.a) {
            case 0:
                d();
                int i = this.b + 1;
                this.c = i;
                q qVar = (q) this.e;
                r.a(i, qVar.size());
                Object obj = qVar.get(i);
                this.b = i;
                return obj;
            case 1:
                Object[] objArr = ((androidx.compose.ui.node.r) this.e).a;
                int i2 = this.b;
                this.b = i2 + 1;
                Object obj2 = objArr[i2];
                Intrinsics.e(obj2, "null cannot be cast to non-null type androidx.compose.ui.Modifier.Node");
                return (androidx.compose.ui.p) obj2;
            case 2:
                a();
                int i3 = this.b;
                kotlin.collections.builders.b bVar = (kotlin.collections.builders.b) this.e;
                if (i3 >= bVar.c) {
                    throw new NoSuchElementException();
                }
                this.b = i3 + 1;
                this.c = i3;
                return bVar.a[bVar.b + i3];
            default:
                b();
                int i4 = this.b;
                kotlin.collections.builders.d dVar = (kotlin.collections.builders.d) this.e;
                if (i4 >= dVar.b) {
                    throw new NoSuchElementException();
                }
                this.b = i4 + 1;
                this.c = i4;
                return dVar.a[i4];
        }
    }

    @Override // java.util.ListIterator
    public final int nextIndex() {
        switch (this.a) {
        }
        return this.b;
    }

    @Override // java.util.ListIterator
    public final Object previous() {
        switch (this.a) {
            case 0:
                d();
                int i = this.b;
                q qVar = (q) this.e;
                r.a(i, qVar.size());
                int i2 = this.b;
                this.c = i2;
                this.b--;
                return qVar.get(i2);
            case 1:
                Object[] objArr = ((androidx.compose.ui.node.r) this.e).a;
                int i3 = this.b - 1;
                this.b = i3;
                Object obj = objArr[i3];
                Intrinsics.e(obj, "null cannot be cast to non-null type androidx.compose.ui.Modifier.Node");
                return (androidx.compose.ui.p) obj;
            case 2:
                a();
                int i4 = this.b;
                if (i4 <= 0) {
                    throw new NoSuchElementException();
                }
                int i5 = i4 - 1;
                this.b = i5;
                this.c = i5;
                kotlin.collections.builders.b bVar = (kotlin.collections.builders.b) this.e;
                return bVar.a[bVar.b + i5];
            default:
                b();
                int i6 = this.b;
                if (i6 <= 0) {
                    throw new NoSuchElementException();
                }
                int i7 = i6 - 1;
                this.b = i7;
                this.c = i7;
                return ((kotlin.collections.builders.d) this.e).a[i7];
        }
    }

    @Override // java.util.ListIterator
    public final int previousIndex() {
        switch (this.a) {
        }
        return this.b - 1;
    }

    @Override // java.util.ListIterator, java.util.Iterator
    public final void remove() {
        switch (this.a) {
            case 0:
                d();
                int i = this.b;
                q qVar = (q) this.e;
                qVar.remove(i);
                this.b--;
                this.c = -1;
                this.d = qVar.i();
                return;
            case 1:
                throw new UnsupportedOperationException("Operation is not supported for read-only collection");
            case 2:
                a();
                int i2 = this.c;
                if (i2 == -1) {
                    throw new IllegalStateException("Call next() or previous() before removing element from the iterator.");
                }
                kotlin.collections.builders.b bVar = (kotlin.collections.builders.b) this.e;
                bVar.b(i2);
                this.b = this.c;
                this.c = -1;
                this.d = ((AbstractList) bVar).modCount;
                return;
            default:
                b();
                int i3 = this.c;
                if (i3 == -1) {
                    throw new IllegalStateException("Call next() or previous() before removing element from the iterator.");
                }
                kotlin.collections.builders.d dVar = (kotlin.collections.builders.d) this.e;
                dVar.b(i3);
                this.b = this.c;
                this.c = -1;
                this.d = ((AbstractList) dVar).modCount;
                return;
        }
    }

    @Override // java.util.ListIterator
    public final void set(Object obj) {
        switch (this.a) {
            case 0:
                d();
                int i = this.c;
                if (i < 0) {
                    throw new IllegalStateException("Cannot call set before the first call to next() or previous() or immediately after a call to add() or remove()");
                }
                q qVar = (q) this.e;
                qVar.set(i, obj);
                this.d = qVar.i();
                return;
            case 1:
                throw new UnsupportedOperationException("Operation is not supported for read-only collection");
            case 2:
                a();
                int i2 = this.c;
                if (i2 == -1) {
                    throw new IllegalStateException("Call next() or previous() before replacing element from the iterator.");
                }
                ((kotlin.collections.builders.b) this.e).set(i2, obj);
                return;
            default:
                b();
                int i3 = this.c;
                if (i3 == -1) {
                    throw new IllegalStateException("Call next() or previous() before replacing element from the iterator.");
                }
                ((kotlin.collections.builders.d) this.e).set(i3, obj);
                return;
        }
    }

    public w(androidx.compose.ui.node.r rVar, int i, int i2, int i3) {
        this.a = 1;
        this.e = rVar;
        this.b = i;
        this.c = i2;
        this.d = i3;
    }

    public w(kotlin.collections.builders.d list, int i) {
        this.a = 3;
        Intrinsics.checkNotNullParameter(list, "list");
        this.e = list;
        this.b = i;
        this.c = -1;
        this.d = ((AbstractList) list).modCount;
    }

    public w(q qVar, int i) {
        this.a = 0;
        this.e = qVar;
        this.b = i - 1;
        this.c = -1;
        this.d = qVar.i();
    }

    public w(kotlin.collections.builders.b list, int i) {
        this.a = 2;
        Intrinsics.checkNotNullParameter(list, "list");
        this.e = list;
        this.b = i;
        this.c = -1;
        this.d = ((AbstractList) list).modCount;
    }
}
