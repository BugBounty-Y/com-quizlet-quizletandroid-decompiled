package kotlin.ranges;

import java.util.NoSuchElementException;
import kotlin.collections.AbstractC4934z;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class c extends AbstractC4934z {
    public final int a;
    public final int b;
    public boolean c;
    public int d;

    public c(char c, char c2, int i) {
        this.a = i;
        this.b = c2;
        boolean z = false;
        if (i <= 0 ? Intrinsics.g(c, c2) >= 0 : Intrinsics.g(c, c2) <= 0) {
            z = true;
        }
        this.c = z;
        this.d = z ? c : c2;
    }

    @Override // kotlin.collections.AbstractC4934z
    public final char a() {
        int i = this.d;
        if (i != this.b) {
            this.d = this.a + i;
        } else {
            if (!this.c) {
                throw new NoSuchElementException();
            }
            this.c = false;
        }
        return (char) i;
    }

    @Override // java.util.Iterator
    public final boolean hasNext() {
        return this.c;
    }
}
