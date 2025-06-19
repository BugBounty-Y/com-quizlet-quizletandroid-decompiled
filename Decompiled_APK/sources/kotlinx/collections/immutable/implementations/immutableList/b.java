package kotlinx.collections.immutable.implementations.immutableList;

import java.util.NoSuchElementException;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b extends androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableList.a {
    public final /* synthetic */ int d = 1;
    public final Object e;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(Object[] buffer, int i, int i2) {
        super(i, i2, 1);
        Intrinsics.checkNotNullParameter(buffer, "buffer");
        this.e = buffer;
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

    public b(Object obj, int i) {
        super(i, 1, 1);
        this.e = obj;
    }
}
