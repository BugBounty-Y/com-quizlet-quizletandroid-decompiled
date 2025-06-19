package kotlinx.coroutines.internal;

import java.util.Arrays;
import java.util.concurrent.atomic.AtomicIntegerFieldUpdater;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.W;
import kotlinx.coroutines.X;

/* loaded from: classes3.dex */
public class u {
    public static final /* synthetic */ AtomicIntegerFieldUpdater b = AtomicIntegerFieldUpdater.newUpdater(u.class, "_size$volatile");
    private volatile /* synthetic */ int _size$volatile;
    public W[] a;

    public final void a(W w) {
        w.b((X) this);
        W[] wArr = this.a;
        AtomicIntegerFieldUpdater atomicIntegerFieldUpdater = b;
        if (wArr == null) {
            wArr = new W[4];
            this.a = wArr;
        } else if (atomicIntegerFieldUpdater.get(this) >= wArr.length) {
            Object[] objArrCopyOf = Arrays.copyOf(wArr, atomicIntegerFieldUpdater.get(this) * 2);
            Intrinsics.checkNotNullExpressionValue(objArrCopyOf, "copyOf(...)");
            wArr = (W[]) objArrCopyOf;
            this.a = wArr;
        }
        int i = atomicIntegerFieldUpdater.get(this);
        atomicIntegerFieldUpdater.set(this, i + 1);
        wArr[i] = w;
        w.b = i;
        c(i);
    }

    /* JADX WARN: Removed duplicated region for block: B:17:0x0063  */
    /* JADX WARN: Removed duplicated region for block: B:26:? A[SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final kotlinx.coroutines.W b(int r9) {
        /*
            r8 = this;
            kotlinx.coroutines.W[] r0 = r8.a
            kotlin.jvm.internal.Intrinsics.d(r0)
            java.util.concurrent.atomic.AtomicIntegerFieldUpdater r1 = kotlinx.coroutines.internal.u.b
            int r2 = r1.get(r8)
            r3 = -1
            int r2 = r2 + r3
            r1.set(r8, r2)
            int r2 = r1.get(r8)
            if (r9 >= r2) goto L7a
            int r2 = r1.get(r8)
            r8.d(r9, r2)
            int r2 = r9 + (-1)
            int r2 = r2 / 2
            if (r9 <= 0) goto L3a
            r4 = r0[r9]
            kotlin.jvm.internal.Intrinsics.d(r4)
            r5 = r0[r2]
            kotlin.jvm.internal.Intrinsics.d(r5)
            int r4 = r4.compareTo(r5)
            if (r4 >= 0) goto L3a
            r8.d(r9, r2)
            r8.c(r2)
            goto L7a
        L3a:
            int r2 = r9 * 2
            int r4 = r2 + 1
            int r5 = r1.get(r8)
            if (r4 < r5) goto L45
            goto L7a
        L45:
            kotlinx.coroutines.W[] r5 = r8.a
            kotlin.jvm.internal.Intrinsics.d(r5)
            int r2 = r2 + 2
            int r6 = r1.get(r8)
            if (r2 >= r6) goto L63
            r6 = r5[r2]
            kotlin.jvm.internal.Intrinsics.d(r6)
            r7 = r5[r4]
            kotlin.jvm.internal.Intrinsics.d(r7)
            int r6 = r6.compareTo(r7)
            if (r6 >= 0) goto L63
            goto L64
        L63:
            r2 = r4
        L64:
            r4 = r5[r9]
            kotlin.jvm.internal.Intrinsics.d(r4)
            r5 = r5[r2]
            kotlin.jvm.internal.Intrinsics.d(r5)
            int r4 = r4.compareTo(r5)
            if (r4 > 0) goto L75
            goto L7a
        L75:
            r8.d(r9, r2)
            r9 = r2
            goto L3a
        L7a:
            int r9 = r1.get(r8)
            r9 = r0[r9]
            kotlin.jvm.internal.Intrinsics.d(r9)
            r2 = 0
            r9.b(r2)
            r9.b = r3
            int r1 = r1.get(r8)
            r0[r1] = r2
            return r9
        */
        throw new UnsupportedOperationException("Method not decompiled: kotlinx.coroutines.internal.u.b(int):kotlinx.coroutines.W");
    }

    public final void c(int i) {
        while (i > 0) {
            W[] wArr = this.a;
            Intrinsics.d(wArr);
            int i2 = (i - 1) / 2;
            W w = wArr[i2];
            Intrinsics.d(w);
            W w2 = wArr[i];
            Intrinsics.d(w2);
            if (w.compareTo(w2) <= 0) {
                return;
            }
            d(i, i2);
            i = i2;
        }
    }

    public final void d(int i, int i2) {
        W[] wArr = this.a;
        Intrinsics.d(wArr);
        W w = wArr[i2];
        Intrinsics.d(w);
        W w2 = wArr[i];
        Intrinsics.d(w2);
        wArr[i] = w;
        wArr[i2] = w2;
        w.b = i;
        w2.b = i2;
    }
}
