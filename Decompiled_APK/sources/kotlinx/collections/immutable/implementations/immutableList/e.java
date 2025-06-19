package kotlinx.collections.immutable.implementations.immutableList;

import java.util.NoSuchElementException;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class e extends androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableList.a {
    public final Object[] d;
    public final h e;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public e(Object[] root, int i, Object[] tail, int i2, int i3) {
        super(i, i2, 1);
        Intrinsics.checkNotNullParameter(root, "root");
        Intrinsics.checkNotNullParameter(tail, "tail");
        this.d = tail;
        int i4 = (i2 - 1) & (-32);
        this.e = new h(root, i > i4 ? i4 : i, i4, i3);
    }

    @Override // java.util.ListIterator, java.util.Iterator
    public final Object next() {
        if (!hasNext()) {
            throw new NoSuchElementException();
        }
        h hVar = this.e;
        if (hVar.hasNext()) {
            this.b++;
            return hVar.next();
        }
        int i = this.b;
        this.b = i + 1;
        return this.d[i - hVar.c];
    }

    @Override // java.util.ListIterator
    public final Object previous() {
        if (!hasPrevious()) {
            throw new NoSuchElementException();
        }
        int i = this.b;
        h hVar = this.e;
        int i2 = hVar.c;
        if (i <= i2) {
            this.b = i - 1;
            return hVar.previous();
        }
        int i3 = i - 1;
        this.b = i3;
        return this.d[i3 - i2];
    }
}
