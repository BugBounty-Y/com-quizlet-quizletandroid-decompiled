package kotlin.collections;

import java.util.ListIterator;
import java.util.NoSuchElementException;

/* renamed from: kotlin.collections.e, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4914e extends androidx.collection.Y implements ListIterator {
    public final /* synthetic */ AbstractC4916g d;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4914e(AbstractC4916g abstractC4916g, int i) {
        super(abstractC4916g, 5);
        this.d = abstractC4916g;
        C4913d c4913d = AbstractC4916g.a;
        int iA = abstractC4916g.a();
        c4913d.getClass();
        C4913d.c(i, iA);
        this.b = i;
    }

    @Override // java.util.ListIterator
    public final void add(Object obj) {
        throw new UnsupportedOperationException("Operation is not supported for read-only collection");
    }

    @Override // java.util.ListIterator
    public final boolean hasPrevious() {
        return this.b > 0;
    }

    @Override // java.util.ListIterator
    public final int nextIndex() {
        return this.b;
    }

    @Override // java.util.ListIterator
    public final Object previous() {
        if (!hasPrevious()) {
            throw new NoSuchElementException();
        }
        int i = this.b - 1;
        this.b = i;
        return this.d.get(i);
    }

    @Override // java.util.ListIterator
    public final int previousIndex() {
        return this.b - 1;
    }

    @Override // java.util.ListIterator
    public final void set(Object obj) {
        throw new UnsupportedOperationException("Operation is not supported for read-only collection");
    }
}
