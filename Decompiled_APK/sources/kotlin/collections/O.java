package kotlin.collections;

import java.util.Iterator;
import java.util.NoSuchElementException;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class O implements Iterator, kotlin.jvm.internal.markers.a {
    public final /* synthetic */ int a = 0;
    public final Iterator b;
    public int c;

    public O(Iterator iterator) {
        Intrinsics.checkNotNullParameter(iterator, "iterator");
        this.b = iterator;
    }

    @Override // java.util.Iterator
    public final boolean hasNext() {
        Iterator it2;
        switch (this.a) {
            case 0:
                return this.b.hasNext();
            case 1:
                break;
            default:
                return this.c > 0 && this.b.hasNext();
        }
        while (true) {
            int i = this.c;
            it2 = this.b;
            if (i > 0 && it2.hasNext()) {
                it2.next();
                this.c--;
            }
        }
        return it2.hasNext();
    }

    @Override // java.util.Iterator
    public final Object next() {
        Iterator it2;
        switch (this.a) {
            case 0:
                int i = this.c;
                this.c = i + 1;
                if (i >= 0) {
                    return new IndexedValue(i, this.b.next());
                }
                B.p();
                throw null;
            case 1:
                break;
            default:
                int i2 = this.c;
                if (i2 == 0) {
                    throw new NoSuchElementException();
                }
                this.c = i2 - 1;
                return this.b.next();
        }
        while (true) {
            int i3 = this.c;
            it2 = this.b;
            if (i3 > 0 && it2.hasNext()) {
                it2.next();
                this.c--;
            }
        }
        return it2.next();
    }

    @Override // java.util.Iterator
    public final void remove() {
        switch (this.a) {
            case 0:
                throw new UnsupportedOperationException("Operation is not supported for read-only collection");
            case 1:
                throw new UnsupportedOperationException("Operation is not supported for read-only collection");
            default:
                throw new UnsupportedOperationException("Operation is not supported for read-only collection");
        }
    }

    public O(kotlin.sequences.s sVar) {
        sVar.getClass();
        this.c = 7;
        this.b = sVar.a.iterator();
    }

    public O(kotlin.sequences.b bVar) {
        this.b = bVar.a.iterator();
        this.c = bVar.b;
    }
}
