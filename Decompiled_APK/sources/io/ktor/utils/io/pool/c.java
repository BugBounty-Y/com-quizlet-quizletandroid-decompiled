package io.ktor.utils.io.pool;

import java.util.concurrent.atomic.AtomicLongFieldUpdater;
import java.util.concurrent.atomic.AtomicReferenceArray;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes3.dex */
public abstract class c implements AutoCloseable {
    public static final /* synthetic */ AtomicLongFieldUpdater c = AtomicLongFieldUpdater.newUpdater(c.class, "top");
    public final AtomicReferenceArray a;
    public final int[] b;

    @NotNull
    private volatile /* synthetic */ long top = 0;

    public c() {
        int iHighestOneBit = Integer.highestOneBit(511) * 2;
        Integer.numberOfLeadingZeros(iHighestOneBit);
        int i = iHighestOneBit + 1;
        this.a = new AtomicReferenceArray(i);
        this.b = new int[i];
    }

    /* JADX WARN: Removed duplicated region for block: B:13:0x0032  */
    /* JADX WARN: Removed duplicated region for block: B:16:0x003b  */
    /* JADX WARN: Removed duplicated region for block: B:17:0x003a A[SYNTHETIC] */
    @Override // java.lang.AutoCloseable
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void close() {
        /*
            r10 = this;
        L0:
            long r2 = r10.top
            r0 = 0
            int r0 = (r2 > r0 ? 1 : (r2 == r0 ? 0 : -1))
            r1 = 0
            if (r0 != 0) goto Lc
        L9:
            r6 = r1
            r1 = r10
            goto L2e
        Lc:
            r0 = 32
            long r4 = r2 >> r0
            r6 = 4294967295(0xffffffff, double:2.1219957905E-314)
            long r4 = r4 & r6
            r8 = 1
            long r4 = r4 + r8
            long r6 = r6 & r2
            int r6 = (int) r6
            if (r6 != 0) goto L1e
            goto L9
        L1e:
            int[] r1 = r10.b
            r1 = r1[r6]
            long r4 = r4 << r0
            long r0 = (long) r1
            long r4 = r4 | r0
            java.util.concurrent.atomic.AtomicLongFieldUpdater r0 = io.ktor.utils.io.pool.c.c
            r1 = r10
            boolean r0 = r0.compareAndSet(r1, r2, r4)
            if (r0 == 0) goto L0
        L2e:
            r0 = 0
            if (r6 != 0) goto L32
            goto L38
        L32:
            java.util.concurrent.atomic.AtomicReferenceArray r2 = r1.a
            java.lang.Object r0 = r2.getAndSet(r6, r0)
        L38:
            if (r0 != 0) goto L3b
            return
        L3b:
            java.lang.String r2 = "instance"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r0, r2)
            goto L0
        */
        throw new UnsupportedOperationException("Method not decompiled: io.ktor.utils.io.pool.c.close():void");
    }
}
