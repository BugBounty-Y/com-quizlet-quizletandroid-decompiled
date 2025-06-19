package androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableList;

import java.util.NoSuchElementException;

/* loaded from: classes.dex */
public final class d extends a {
    public final /* synthetic */ int d = 1;
    public final Object e;

    public d(Object[] objArr, int i, int i2) {
        super(i, i2, 0);
        this.e = objArr;
    }

    @Override // java.util.ListIterator, java.util.Iterator
    public final Object next() {
        switch (this.d) {
            case 0:
                if (!hasNext()) {
                    throw new NoSuchElementException();
                }
                int i = this.b;
                this.b = i + 1;
                return ((Object[]) this.e)[i];
            default:
                if (!hasNext()) {
                    throw new NoSuchElementException();
                }
                this.b++;
                return this.e;
        }
    }

    @Override // java.util.ListIterator
    public final Object previous() {
        switch (this.d) {
            case 0:
                if (!hasPrevious()) {
                    throw new NoSuchElementException();
                }
                int i = this.b - 1;
                this.b = i;
                return ((Object[]) this.e)[i];
            default:
                if (!hasPrevious()) {
                    throw new NoSuchElementException();
                }
                this.b--;
                return this.e;
        }
    }

    public d(Object obj, int i) {
        super(i, 1, 0);
        this.e = obj;
    }
}
