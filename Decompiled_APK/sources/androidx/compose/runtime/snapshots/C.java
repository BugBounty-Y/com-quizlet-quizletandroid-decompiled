package androidx.compose.runtime.snapshots;

import java.util.List;
import java.util.ListIterator;
import kotlin.collections.W;
import kotlin.jvm.internal.H;
import kotlin.ranges.IntRange;

/* loaded from: classes.dex */
public final class C implements ListIterator, kotlin.jvm.internal.markers.a {
    public final /* synthetic */ int a = 1;
    public final Object b;
    public final /* synthetic */ Object c;

    public C(W w, int i) {
        this.c = w;
        if (i >= 0 && i <= w.a()) {
            this.b = ((List) w.c).listIterator(w.a() - i);
        } else {
            StringBuilder sbV = android.support.v4.media.session.a.v(i, "Position index ", " must be in range [");
            sbV.append(new IntRange(0, w.a(), 1));
            sbV.append("].");
            throw new IndexOutOfBoundsException(sbV.toString());
        }
    }

    @Override // java.util.ListIterator
    public final void add(Object obj) {
        switch (this.a) {
            case 0:
                throw new IllegalStateException("Cannot modify a state list through an iterator");
            default:
                throw new UnsupportedOperationException("Operation is not supported for read-only collection");
        }
    }

    @Override // java.util.ListIterator, java.util.Iterator
    public final boolean hasNext() {
        switch (this.a) {
            case 0:
                return ((H) this.b).a < ((D) this.c).d - 1;
            default:
                return ((ListIterator) this.b).hasPrevious();
        }
    }

    @Override // java.util.ListIterator
    public final boolean hasPrevious() {
        switch (this.a) {
            case 0:
                return ((H) this.b).a >= 0;
            default:
                return ((ListIterator) this.b).hasNext();
        }
    }

    @Override // java.util.ListIterator, java.util.Iterator
    public final Object next() {
        switch (this.a) {
            case 0:
                H h = (H) this.b;
                int i = h.a + 1;
                D d = (D) this.c;
                r.a(i, d.d);
                h.a = i;
                return d.get(i);
            default:
                return ((ListIterator) this.b).previous();
        }
    }

    @Override // java.util.ListIterator
    public final int nextIndex() {
        switch (this.a) {
            case 0:
                return ((H) this.b).a + 1;
            default:
                return kotlin.collections.B.i((W) this.c) - ((ListIterator) this.b).previousIndex();
        }
    }

    @Override // java.util.ListIterator
    public final Object previous() {
        switch (this.a) {
            case 0:
                H h = (H) this.b;
                int i = h.a;
                D d = (D) this.c;
                r.a(i, d.d);
                h.a = i - 1;
                return d.get(i);
            default:
                return ((ListIterator) this.b).next();
        }
    }

    @Override // java.util.ListIterator
    public final int previousIndex() {
        switch (this.a) {
            case 0:
                return ((H) this.b).a;
            default:
                return kotlin.collections.B.i((W) this.c) - ((ListIterator) this.b).nextIndex();
        }
    }

    @Override // java.util.ListIterator, java.util.Iterator
    public final void remove() {
        switch (this.a) {
            case 0:
                throw new IllegalStateException("Cannot modify a state list through an iterator");
            default:
                throw new UnsupportedOperationException("Operation is not supported for read-only collection");
        }
    }

    @Override // java.util.ListIterator
    public final void set(Object obj) {
        switch (this.a) {
            case 0:
                throw new IllegalStateException("Cannot modify a state list through an iterator");
            default:
                throw new UnsupportedOperationException("Operation is not supported for read-only collection");
        }
    }

    public C(H h, D d) {
        this.b = h;
        this.c = d;
    }
}
