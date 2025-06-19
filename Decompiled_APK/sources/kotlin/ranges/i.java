package kotlin.ranges;

import java.util.NoSuchElementException;
import kotlin.collections.P;

/* loaded from: classes3.dex */
public final class i extends P {
    public final int a;
    public final int b;
    public boolean c;
    public int d;

    public i(int i, int i2, int i3) {
        this.a = i3;
        this.b = i2;
        boolean z = false;
        if (i3 <= 0 ? i >= i2 : i <= i2) {
            z = true;
        }
        this.c = z;
        this.d = z ? i : i2;
    }

    @Override // java.util.Iterator
    public final boolean hasNext() {
        return this.c;
    }

    @Override // kotlin.collections.P
    public final int nextInt() {
        int i = this.d;
        if (i != this.b) {
            this.d = this.a + i;
            return i;
        }
        if (!this.c) {
            throw new NoSuchElementException();
        }
        this.c = false;
        return i;
    }
}
