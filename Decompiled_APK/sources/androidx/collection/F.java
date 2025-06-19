package androidx.collection;

import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.ListIterator;
import kotlin.jvm.internal.AbstractC4958q;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class F implements List, kotlin.jvm.internal.markers.c {
    public final /* synthetic */ int a;
    public final Object b;
    public final int c;
    public int d;

    public F(List list, int i, int i2, int i3) {
        this.a = i3;
        switch (i3) {
            case 1:
                this.b = list;
                this.c = i;
                this.d = i2;
                break;
            default:
                Intrinsics.checkNotNullParameter(list, "list");
                this.b = list;
                this.c = i;
                this.d = i2;
                break;
        }
    }

    /* JADX WARN: Type inference failed for: r1v1, types: [java.lang.Object, java.util.List] */
    /* JADX WARN: Type inference failed for: r1v3, types: [java.lang.Object, java.util.List] */
    @Override // java.util.List, java.util.Collection
    public final boolean add(Object obj) {
        switch (this.a) {
            case 0:
                int i = this.d;
                this.d = i + 1;
                this.b.add(i, obj);
                break;
            default:
                int i2 = this.d;
                this.d = i2 + 1;
                this.b.add(i2, obj);
                break;
        }
        return true;
    }

    /* JADX WARN: Type inference failed for: r0v3, types: [java.lang.Object, java.util.List] */
    /* JADX WARN: Type inference failed for: r0v7, types: [java.lang.Object, java.util.List] */
    @Override // java.util.List
    public final boolean addAll(int i, Collection elements) {
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter(elements, "elements");
                this.b.addAll(i + this.c, elements);
                this.d = elements.size() + this.d;
                if (elements.size() > 0) {
                }
                break;
            default:
                this.b.addAll(i + this.c, elements);
                int size = elements.size();
                this.d += size;
                if (size > 0) {
                }
                break;
        }
        return false;
    }

    /* JADX WARN: Type inference failed for: r2v0, types: [java.lang.Object, java.util.List] */
    /* JADX WARN: Type inference failed for: r2v1, types: [java.lang.Object, java.util.List] */
    @Override // java.util.List, java.util.Collection
    public final void clear() {
        switch (this.a) {
            case 0:
                int i = this.d - 1;
                int i2 = this.c;
                if (i2 <= i) {
                    while (true) {
                        this.b.remove(i);
                        if (i != i2) {
                            i--;
                        }
                    }
                }
                this.d = i2;
                break;
            default:
                int i3 = this.d - 1;
                int i4 = this.c;
                if (i4 <= i3) {
                    while (true) {
                        this.b.remove(i3);
                        if (i3 != i4) {
                            i3--;
                        }
                    }
                }
                this.d = i4;
                break;
        }
    }

    /* JADX WARN: Type inference failed for: r2v0, types: [java.lang.Object, java.util.List] */
    /* JADX WARN: Type inference failed for: r2v3, types: [java.lang.Object, java.util.List] */
    @Override // java.util.List, java.util.Collection
    public final boolean contains(Object obj) {
        switch (this.a) {
            case 0:
                int i = this.d;
                for (int i2 = this.c; i2 < i; i2++) {
                    if (Intrinsics.b(this.b.get(i2), obj)) {
                        break;
                    }
                }
                break;
            default:
                int i3 = this.d;
                for (int i4 = this.c; i4 < i3; i4++) {
                    if (Intrinsics.b(this.b.get(i4), obj)) {
                        break;
                    }
                }
                break;
        }
        return false;
    }

    @Override // java.util.List, java.util.Collection
    public final boolean containsAll(Collection elements) {
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter(elements, "elements");
                Iterator it2 = elements.iterator();
                while (it2.hasNext()) {
                    if (!contains(it2.next())) {
                        break;
                    }
                }
                break;
            default:
                Iterator it3 = elements.iterator();
                while (it3.hasNext()) {
                    if (!contains(it3.next())) {
                        break;
                    }
                }
                break;
        }
        return true;
    }

    /* JADX WARN: Type inference failed for: r0v2, types: [java.lang.Object, java.util.List] */
    /* JADX WARN: Type inference failed for: r0v4, types: [java.lang.Object, java.util.List] */
    @Override // java.util.List
    public final Object get(int i) {
        switch (this.a) {
            case 0:
                P.a(i, this);
                return this.b.get(i + this.c);
            default:
                androidx.compose.runtime.collection.c.a(i, this);
                return this.b.get(i + this.c);
        }
    }

    /* JADX WARN: Type inference failed for: r3v0, types: [java.lang.Object, java.util.List] */
    /* JADX WARN: Type inference failed for: r3v3, types: [java.lang.Object, java.util.List] */
    @Override // java.util.List
    public final int indexOf(Object obj) {
        switch (this.a) {
            case 0:
                int i = this.d;
                int i2 = this.c;
                for (int i3 = i2; i3 < i; i3++) {
                    if (Intrinsics.b(this.b.get(i3), obj)) {
                        return i3 - i2;
                    }
                }
                return -1;
            default:
                int i4 = this.d;
                int i5 = this.c;
                for (int i6 = i5; i6 < i4; i6++) {
                    if (Intrinsics.b(this.b.get(i6), obj)) {
                        return i6 - i5;
                    }
                }
                return -1;
        }
    }

    @Override // java.util.List, java.util.Collection
    public final boolean isEmpty() {
        switch (this.a) {
            case 0:
                if (this.d == this.c) {
                }
                break;
            default:
                if (this.d == this.c) {
                }
                break;
        }
        return false;
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

    /* JADX WARN: Type inference failed for: r2v0, types: [java.lang.Object, java.util.List] */
    /* JADX WARN: Type inference failed for: r2v3, types: [java.lang.Object, java.util.List] */
    @Override // java.util.List
    public final int lastIndexOf(Object obj) {
        switch (this.a) {
            case 0:
                int i = this.d - 1;
                int i2 = this.c;
                if (i2 <= i) {
                    while (!Intrinsics.b(this.b.get(i), obj)) {
                        if (i != i2) {
                            i--;
                        }
                    }
                    return i - i2;
                }
                return -1;
            default:
                int i3 = this.d - 1;
                int i4 = this.c;
                if (i4 <= i3) {
                    while (!Intrinsics.b(this.b.get(i3), obj)) {
                        if (i3 != i4) {
                            i3--;
                        }
                    }
                    return i3 - i4;
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

    /* JADX WARN: Type inference failed for: r2v0, types: [java.lang.Object, java.util.List] */
    /* JADX WARN: Type inference failed for: r2v1, types: [java.lang.Object, java.util.List] */
    @Override // java.util.List, java.util.Collection
    public final boolean remove(Object obj) {
        switch (this.a) {
            case 0:
                int i = this.d;
                for (int i2 = this.c; i2 < i; i2++) {
                    ?? r2 = this.b;
                    if (Intrinsics.b(r2.get(i2), obj)) {
                        r2.remove(i2);
                        this.d--;
                        break;
                    }
                }
                break;
            default:
                int i3 = this.d;
                for (int i4 = this.c; i4 < i3; i4++) {
                    ?? r22 = this.b;
                    if (Intrinsics.b(r22.get(i4), obj)) {
                        r22.remove(i4);
                        this.d--;
                        break;
                    }
                }
                break;
        }
        return true;
    }

    @Override // java.util.List, java.util.Collection
    public final boolean removeAll(Collection elements) {
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter(elements, "elements");
                int i = this.d;
                Iterator it2 = elements.iterator();
                while (it2.hasNext()) {
                    remove(it2.next());
                }
                if (i != this.d) {
                }
                break;
            default:
                int i2 = this.d;
                Iterator it3 = elements.iterator();
                while (it3.hasNext()) {
                    remove(it3.next());
                }
                if (i2 != this.d) {
                }
                break;
        }
        return false;
    }

    /* JADX WARN: Type inference failed for: r3v0, types: [java.lang.Object, java.util.List] */
    /* JADX WARN: Type inference failed for: r3v3, types: [java.lang.Object, java.util.List] */
    @Override // java.util.List, java.util.Collection
    public final boolean retainAll(Collection elements) {
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter(elements, "elements");
                int i = this.d;
                int i2 = i - 1;
                int i3 = this.c;
                if (i3 <= i2) {
                    while (true) {
                        ?? r3 = this.b;
                        if (!elements.contains(r3.get(i2))) {
                            r3.remove(i2);
                            this.d--;
                        }
                        if (i2 != i3) {
                            i2--;
                        }
                    }
                }
                if (i != this.d) {
                }
                break;
            default:
                int i4 = this.d;
                int i5 = i4 - 1;
                int i6 = this.c;
                if (i6 <= i5) {
                    while (true) {
                        ?? r32 = this.b;
                        if (!elements.contains(r32.get(i5))) {
                            r32.remove(i5);
                            this.d--;
                        }
                        if (i5 != i6) {
                            i5--;
                        }
                    }
                }
                if (i4 != this.d) {
                }
                break;
        }
        return false;
    }

    /* JADX WARN: Type inference failed for: r0v2, types: [java.lang.Object, java.util.List] */
    /* JADX WARN: Type inference failed for: r0v4, types: [java.lang.Object, java.util.List] */
    @Override // java.util.List
    public final Object set(int i, Object obj) {
        switch (this.a) {
            case 0:
                P.a(i, this);
                return this.b.set(i + this.c, obj);
            default:
                androidx.compose.runtime.collection.c.a(i, this);
                return this.b.set(i + this.c, obj);
        }
    }

    @Override // java.util.List, java.util.Collection
    public final int size() {
        switch (this.a) {
        }
        return this.d - this.c;
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

    /* JADX WARN: Type inference failed for: r0v2, types: [java.lang.Object, java.util.List] */
    /* JADX WARN: Type inference failed for: r0v4, types: [java.lang.Object, java.util.List] */
    @Override // java.util.List
    public final void add(int i, Object obj) {
        switch (this.a) {
            case 0:
                this.b.add(i + this.c, obj);
                this.d++;
                break;
            default:
                this.b.add(i + this.c, obj);
                this.d++;
                break;
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

    @Override // java.util.List, java.util.Collection
    public final Object[] toArray(Object[] array) {
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter(array, "array");
                break;
        }
        return AbstractC4958q.b(this, array);
    }

    /* JADX WARN: Type inference failed for: r0v2, types: [java.lang.Object, java.util.List] */
    /* JADX WARN: Type inference failed for: r0v4, types: [java.lang.Object, java.util.List] */
    @Override // java.util.List, java.util.Collection
    public final boolean addAll(Collection elements) {
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter(elements, "elements");
                this.b.addAll(this.d, elements);
                this.d = elements.size() + this.d;
                if (elements.size() > 0) {
                }
                break;
            default:
                this.b.addAll(this.d, elements);
                int size = elements.size();
                this.d += size;
                if (size > 0) {
                }
                break;
        }
        return false;
    }

    /* JADX WARN: Type inference failed for: r0v2, types: [java.lang.Object, java.util.List] */
    /* JADX WARN: Type inference failed for: r0v6, types: [java.lang.Object, java.util.List] */
    @Override // java.util.List
    public final Object remove(int i) {
        switch (this.a) {
            case 0:
                P.a(i, this);
                this.d--;
                return this.b.remove(i + this.c);
            default:
                androidx.compose.runtime.collection.c.a(i, this);
                this.d--;
                return this.b.remove(i + this.c);
        }
    }
}
