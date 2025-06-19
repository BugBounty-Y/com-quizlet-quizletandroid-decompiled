package androidx.compose.runtime;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class D extends androidx.compose.runtime.snapshots.B {
    public static final Object h = new Object();
    public long c;
    public int d;
    public androidx.collection.C e;
    public Object f;
    public int g;

    public D(long j) {
        super(j);
        androidx.collection.C c = androidx.collection.O.a;
        Intrinsics.e(c, "null cannot be cast to non-null type androidx.collection.ObjectIntMap<K of androidx.collection.ObjectIntMapKt.emptyObjectIntMap>");
        this.e = c;
        this.f = h;
    }

    @Override // androidx.compose.runtime.snapshots.B
    public final void a(androidx.compose.runtime.snapshots.B b) {
        Intrinsics.e(b, "null cannot be cast to non-null type androidx.compose.runtime.DerivedSnapshotState.ResultRecord<T of androidx.compose.runtime.DerivedSnapshotState.ResultRecord>");
        D d = (D) b;
        this.e = d.e;
        this.f = d.f;
        this.g = d.g;
    }

    @Override // androidx.compose.runtime.snapshots.B
    public final androidx.compose.runtime.snapshots.B b(long j) {
        return new D(j);
    }

    /* JADX WARN: Removed duplicated region for block: B:12:0x001c  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean c(androidx.compose.runtime.E r7, androidx.compose.runtime.snapshots.h r8) {
        /*
            r6 = this;
            java.lang.Object r0 = androidx.compose.runtime.snapshots.m.b
            monitor-enter(r0)
            long r1 = r6.c     // Catch: java.lang.Throwable -> L1a
            long r3 = r8.g()     // Catch: java.lang.Throwable -> L1a
            int r1 = (r1 > r3 ? 1 : (r1 == r3 ? 0 : -1))
            r2 = 1
            r3 = 0
            if (r1 != 0) goto L1c
            int r1 = r6.d     // Catch: java.lang.Throwable -> L1a
            int r4 = r8.h()     // Catch: java.lang.Throwable -> L1a
            if (r1 == r4) goto L18
            goto L1c
        L18:
            r1 = r3
            goto L1d
        L1a:
            r7 = move-exception
            goto L49
        L1c:
            r1 = r2
        L1d:
            monitor-exit(r0)
            java.lang.Object r4 = r6.f
            java.lang.Object r5 = androidx.compose.runtime.D.h
            if (r4 == r5) goto L2f
            if (r1 == 0) goto L30
            int r4 = r6.g
            int r7 = r6.d(r7, r8)
            if (r4 != r7) goto L2f
            goto L30
        L2f:
            r2 = r3
        L30:
            if (r2 == 0) goto L48
            if (r1 == 0) goto L48
            monitor-enter(r0)
            long r3 = r8.g()     // Catch: java.lang.Throwable -> L45
            r6.c = r3     // Catch: java.lang.Throwable -> L45
            int r7 = r8.h()     // Catch: java.lang.Throwable -> L45
            r6.d = r7     // Catch: java.lang.Throwable -> L45
            kotlin.Unit r7 = kotlin.Unit.a     // Catch: java.lang.Throwable -> L45
            monitor-exit(r0)
            return r2
        L45:
            r7 = move-exception
            monitor-exit(r0)
            throw r7
        L48:
            return r2
        L49:
            monitor-exit(r0)
            throw r7
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.runtime.D.c(androidx.compose.runtime.E, androidx.compose.runtime.snapshots.h):boolean");
    }

    /* JADX WARN: Removed duplicated region for block: B:60:0x00fc A[LOOP:3: B:59:0x00fa->B:60:0x00fc, LOOP_END] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final int d(androidx.compose.runtime.E r21, androidx.compose.runtime.snapshots.h r22) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 269
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.runtime.D.d(androidx.compose.runtime.E, androidx.compose.runtime.snapshots.h):int");
    }
}
