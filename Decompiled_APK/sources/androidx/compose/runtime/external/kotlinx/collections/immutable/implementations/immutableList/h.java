package androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableList;

import java.util.NoSuchElementException;

/* loaded from: classes.dex */
public final class h extends a {
    public final Object[] d;
    public final k e;

    public h(Object[] objArr, int i, Object[] objArr2, int i2, int i3) {
        super(i, i2, 0);
        this.d = objArr2;
        int i4 = (i2 - 1) & (-32);
        this.e = new k(objArr, i > i4 ? i4 : i, i4, i3);
    }

    @Override // java.util.ListIterator, java.util.Iterator
    public final Object next() {
        if (!hasNext()) {
            throw new NoSuchElementException();
        }
        k kVar = this.e;
        if (kVar.hasNext()) {
            this.b++;
            return kVar.next();
        }
        int i = this.b;
        this.b = i + 1;
        return this.d[i - kVar.c];
    }

    @Override // java.util.ListIterator
    public final Object previous() {
        if (!hasPrevious()) {
            throw new NoSuchElementException();
        }
        int i = this.b;
        k kVar = this.e;
        int i2 = kVar.c;
        if (i <= i2) {
            this.b = i - 1;
            return kVar.previous();
        }
        int i3 = i - 1;
        this.b = i3;
        return this.d[i3 - i2];
    }
}
