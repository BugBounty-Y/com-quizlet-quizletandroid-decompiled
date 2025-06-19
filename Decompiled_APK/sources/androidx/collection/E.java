package androidx.collection;

import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.ListIterator;
import kotlin.collections.C4930v;
import kotlin.jvm.internal.AbstractC4958q;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class E implements List, kotlin.jvm.internal.markers.c {
    public final /* synthetic */ int a = 0;
    public final Object b;

    public E(androidx.compose.runtime.collection.b bVar) {
        this.b = bVar;
    }

    @Override // java.util.List, java.util.Collection
    public final boolean add(Object obj) {
        switch (this.a) {
            case 0:
                ((G) this.b).a(obj);
                break;
            default:
                ((androidx.compose.runtime.collection.b) this.b).b(obj);
                break;
        }
        return true;
    }

    @Override // java.util.List, java.util.Collection
    public final boolean addAll(Collection elements) {
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter(elements, "elements");
                Collection elements2 = elements;
                G g = (G) this.b;
                Intrinsics.checkNotNullParameter(elements2, "elements");
                int i = g.b;
                Intrinsics.checkNotNullParameter(elements2, "elements");
                Iterator it2 = elements2.iterator();
                while (it2.hasNext()) {
                    g.a(it2.next());
                }
                return i != g.b;
            default:
                androidx.compose.runtime.collection.b bVar = (androidx.compose.runtime.collection.b) this.b;
                return bVar.g(bVar.c, elements);
        }
    }

    @Override // java.util.List, java.util.Collection
    public final void clear() {
        switch (this.a) {
            case 0:
                G g = (G) this.b;
                C4930v.o(g.a, null, 0, g.b);
                g.b = 0;
                break;
            default:
                ((androidx.compose.runtime.collection.b) this.b).i();
                break;
        }
    }

    @Override // java.util.List, java.util.Collection
    public final boolean contains(Object obj) {
        switch (this.a) {
            case 0:
                return ((G) this.b).d(obj) >= 0;
            default:
                return ((androidx.compose.runtime.collection.b) this.b).j(obj);
        }
    }

    @Override // java.util.List, java.util.Collection
    public final boolean containsAll(Collection elements) {
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter(elements, "elements");
                Collection elements2 = elements;
                G g = (G) this.b;
                Intrinsics.checkNotNullParameter(elements2, "elements");
                Iterator it2 = elements2.iterator();
                while (it2.hasNext()) {
                    if (g.d(it2.next()) < 0) {
                        break;
                    }
                }
                break;
            default:
                androidx.compose.runtime.collection.b bVar = (androidx.compose.runtime.collection.b) this.b;
                bVar.getClass();
                Iterator it3 = elements.iterator();
                while (it3.hasNext()) {
                    if (!bVar.j(it3.next())) {
                        break;
                    }
                }
                break;
        }
        return true;
    }

    @Override // java.util.List
    public final Object get(int i) {
        switch (this.a) {
            case 0:
                P.a(i, this);
                return ((G) this.b).c(i);
            default:
                androidx.compose.runtime.collection.c.a(i, this);
                return ((androidx.compose.runtime.collection.b) this.b).a[i];
        }
    }

    @Override // java.util.List
    public final int indexOf(Object obj) {
        switch (this.a) {
            case 0:
                return ((G) this.b).d(obj);
            default:
                return ((androidx.compose.runtime.collection.b) this.b).k(obj);
        }
    }

    @Override // java.util.List, java.util.Collection
    public final boolean isEmpty() {
        switch (this.a) {
            case 0:
                return ((G) this.b).e();
            default:
                return ((androidx.compose.runtime.collection.b) this.b).c == 0;
        }
    }

    @Override // java.util.List, java.util.Collection, java.lang.Iterable
    public final Iterator iterator() {
        switch (this.a) {
            case 0:
                return new D(0, 0, this);
            default:
                return new D(0, 1, this);
        }
    }

    @Override // java.util.List
    public final int lastIndexOf(Object obj) {
        int i;
        switch (this.a) {
            case 0:
                G g = (G) this.b;
                if (obj == null) {
                    Object[] objArr = g.a;
                    i = g.b - 1;
                    while (-1 < i) {
                        if (objArr[i] != null) {
                            i--;
                        }
                    }
                    return -1;
                }
                Object[] objArr2 = g.a;
                i = g.b - 1;
                while (-1 < i) {
                    if (!obj.equals(objArr2[i])) {
                        i--;
                    }
                }
                return -1;
                return i;
            default:
                androidx.compose.runtime.collection.b bVar = (androidx.compose.runtime.collection.b) this.b;
                Object[] objArr3 = bVar.a;
                for (int i2 = bVar.c - 1; i2 >= 0; i2--) {
                    if (Intrinsics.b(obj, objArr3[i2])) {
                        return i2;
                    }
                }
                return -1;
        }
    }

    @Override // java.util.List
    public final ListIterator listIterator() {
        switch (this.a) {
            case 0:
                return new D(0, 0, this);
            default:
                return new D(0, 1, this);
        }
    }

    @Override // java.util.List, java.util.Collection
    public final boolean remove(Object obj) {
        switch (this.a) {
            case 0:
                return ((G) this.b).f(obj);
            default:
                return ((androidx.compose.runtime.collection.b) this.b).n(obj);
        }
    }

    @Override // java.util.List, java.util.Collection
    public final boolean removeAll(Collection elements) {
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter(elements, "elements");
                Collection elements2 = elements;
                G g = (G) this.b;
                g.getClass();
                Intrinsics.checkNotNullParameter(elements2, "elements");
                int i = g.b;
                Intrinsics.checkNotNullParameter(elements2, "elements");
                Iterator it2 = elements2.iterator();
                while (it2.hasNext()) {
                    g.f(it2.next());
                }
                if (i != g.b) {
                }
                break;
            default:
                androidx.compose.runtime.collection.b bVar = (androidx.compose.runtime.collection.b) this.b;
                bVar.getClass();
                if (!elements.isEmpty()) {
                    int i2 = bVar.c;
                    Iterator it3 = elements.iterator();
                    while (it3.hasNext()) {
                        bVar.n(it3.next());
                    }
                    if (i2 != bVar.c) {
                    }
                }
                break;
        }
        return false;
    }

    @Override // java.util.List, java.util.Collection
    public final boolean retainAll(Collection elements) {
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter(elements, "elements");
                G g = (G) this.b;
                g.getClass();
                Intrinsics.checkNotNullParameter(elements, "elements");
                int i = g.b;
                Object[] objArr = g.a;
                for (int i2 = i - 1; -1 < i2; i2--) {
                    if (!elements.contains(objArr[i2])) {
                        g.g(i2);
                    }
                }
                if (i != g.b) {
                }
                break;
            default:
                androidx.compose.runtime.collection.b bVar = (androidx.compose.runtime.collection.b) this.b;
                int i3 = bVar.c;
                for (int i4 = i3 - 1; -1 < i4; i4--) {
                    if (!elements.contains(bVar.a[i4])) {
                        bVar.o(i4);
                    }
                }
                if (i3 != bVar.c) {
                }
                break;
        }
        return false;
    }

    @Override // java.util.List
    public final Object set(int i, Object obj) {
        switch (this.a) {
            case 0:
                P.a(i, this);
                G g = (G) this.b;
                if (i < 0 || i >= g.b) {
                    g.i(i);
                    throw null;
                }
                Object[] objArr = g.a;
                Object obj2 = objArr[i];
                objArr[i] = obj;
                return obj2;
            default:
                androidx.compose.runtime.collection.c.a(i, this);
                Object[] objArr2 = ((androidx.compose.runtime.collection.b) this.b).a;
                Object obj3 = objArr2[i];
                objArr2[i] = obj;
                return obj3;
        }
    }

    @Override // java.util.List, java.util.Collection
    public final int size() {
        switch (this.a) {
            case 0:
                return ((G) this.b).b;
            default:
                return ((androidx.compose.runtime.collection.b) this.b).c;
        }
    }

    @Override // java.util.List
    public final List subList(int i, int i2) {
        switch (this.a) {
            case 0:
                P.b(i, i2, this);
                return new F(this, i, i2, 0);
            default:
                androidx.compose.runtime.collection.c.b(i, i2, this);
                return new F(this, i, i2, 1);
        }
    }

    @Override // java.util.List, java.util.Collection
    public final Object[] toArray() {
        switch (this.a) {
        }
        return AbstractC4958q.a(this);
    }

    public E(G objectList) {
        Intrinsics.checkNotNullParameter(objectList, "objectList");
        this.b = objectList;
    }

    @Override // java.util.List
    public final void add(int i, Object obj) {
        int i2;
        switch (this.a) {
            case 0:
                G g = (G) this.b;
                if (i >= 0 && i <= (i2 = g.b)) {
                    int i3 = i2 + 1;
                    Object[] objArr = g.a;
                    if (objArr.length < i3) {
                        g.h(i3, objArr);
                    }
                    Object[] objArr2 = g.a;
                    int i4 = g.b;
                    if (i != i4) {
                        C4930v.h(objArr2, i + 1, objArr2, i, i4);
                    }
                    objArr2[i] = obj;
                    g.b++;
                    return;
                }
                StringBuilder sbV = android.support.v4.media.session.a.v(i, "Index ", " must be in 0..");
                sbV.append(g.b);
                androidx.collection.internal.a.d(sbV.toString());
                throw null;
            default:
                ((androidx.compose.runtime.collection.b) this.b).a(i, obj);
                return;
        }
    }

    @Override // java.util.List
    public final ListIterator listIterator(int i) {
        switch (this.a) {
            case 0:
                return new D(i, 0, this);
            default:
                return new D(i, 1, this);
        }
    }

    @Override // java.util.List
    public final Object remove(int i) {
        switch (this.a) {
            case 0:
                P.a(i, this);
                return ((G) this.b).g(i);
            default:
                androidx.compose.runtime.collection.c.a(i, this);
                return ((androidx.compose.runtime.collection.b) this.b).o(i);
        }
    }

    @Override // java.util.List, java.util.Collection
    public final Object[] toArray(Object[] array) {
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter(array, "array");
                break;
        }
        return AbstractC4958q.b(this, array);
    }

    @Override // java.util.List
    public final boolean addAll(int i, Collection elements) {
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter(elements, "elements");
                G g = (G) this.b;
                Intrinsics.checkNotNullParameter(elements, "elements");
                if (i >= 0 && i <= g.b) {
                    int i2 = 0;
                    if (elements.isEmpty()) {
                        return false;
                    }
                    int size = elements.size() + g.b;
                    Object[] objArr = g.a;
                    if (objArr.length < size) {
                        g.h(size, objArr);
                    }
                    Object[] objArr2 = g.a;
                    if (i != g.b) {
                        C4930v.h(objArr2, elements.size() + i, objArr2, i, g.b);
                    }
                    for (Object obj : elements) {
                        int i3 = i2 + 1;
                        if (i2 >= 0) {
                            objArr2[i2 + i] = obj;
                            i2 = i3;
                        } else {
                            kotlin.collections.B.p();
                            throw null;
                        }
                    }
                    g.b = elements.size() + g.b;
                    return true;
                }
                StringBuilder sbV = android.support.v4.media.session.a.v(i, "Index ", " must be in 0..");
                sbV.append(g.b);
                androidx.collection.internal.a.d(sbV.toString());
                throw null;
            default:
                return ((androidx.compose.runtime.collection.b) this.b).g(i, elements);
        }
    }
}
