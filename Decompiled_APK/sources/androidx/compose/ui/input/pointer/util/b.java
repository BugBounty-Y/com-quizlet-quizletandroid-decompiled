package androidx.compose.ui.input.pointer.util;

import androidx.compose.animation.d0;
import java.util.Arrays;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class b {
    public int a;
    public long[] b;

    public b(int i) {
        this.b = new long[i];
    }

    public void a(long j) {
        if (b(j)) {
            return;
        }
        int i = this.a;
        long[] jArr = this.b;
        if (i >= jArr.length) {
            long[] jArrCopyOf = Arrays.copyOf(jArr, Math.max(i + 1, jArr.length * 2));
            Intrinsics.checkNotNullExpressionValue(jArrCopyOf, "copyOf(this, newSize)");
            this.b = jArrCopyOf;
        }
        this.b[i] = j;
        if (i >= this.a) {
            this.a = i + 1;
        }
    }

    public boolean b(long j) {
        int i = this.a;
        for (int i2 = 0; i2 < i; i2++) {
            if (this.b[i2] == j) {
                return true;
            }
        }
        return false;
    }

    public void c(int i) {
        int i2 = this.a;
        if (i < i2) {
            int i3 = i2 - 1;
            while (i < i3) {
                long[] jArr = this.b;
                int i4 = i + 1;
                jArr[i] = jArr[i4];
                i = i4;
            }
            this.a--;
        }
    }

    public long d(int i) {
        if (i < 0 || i >= this.a) {
            throw new IndexOutOfBoundsException(d0.p("Invalid index ", i, ", size is ", this.a));
        }
        return this.b[i];
    }

    public void e(long j) {
        int i = this.a;
        long[] jArr = this.b;
        if (i == jArr.length) {
            this.b = Arrays.copyOf(jArr, i + i);
        }
        long[] jArr2 = this.b;
        int i2 = this.a;
        this.a = i2 + 1;
        jArr2[i2] = j;
    }

    public void f(long[] jArr) {
        int i = this.a;
        int length = jArr.length;
        int i2 = i + length;
        long[] jArr2 = this.b;
        int length2 = jArr2.length;
        if (i2 > length2) {
            this.b = Arrays.copyOf(jArr2, Math.max(length2 + length2, i2));
        }
        System.arraycopy(jArr, 0, this.b, this.a, length);
        this.a = i2;
    }
}
