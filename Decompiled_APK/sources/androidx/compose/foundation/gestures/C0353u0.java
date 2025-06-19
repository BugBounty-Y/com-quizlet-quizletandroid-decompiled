package androidx.compose.foundation.gestures;

/* renamed from: androidx.compose.foundation.gestures.u0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0353u0 implements androidx.compose.ui.input.nestedscroll.a {
    public final L0 a;
    public boolean b;

    public C0353u0(L0 l0, boolean z) {
        this.a = l0;
        this.b = z;
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    @Override // androidx.compose.ui.input.nestedscroll.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object p(long r3, long r5, kotlin.coroutines.h r7) {
        /*
            r2 = this;
            boolean r3 = r7 instanceof androidx.compose.foundation.gestures.C0351t0
            if (r3 == 0) goto L13
            r3 = r7
            androidx.compose.foundation.gestures.t0 r3 = (androidx.compose.foundation.gestures.C0351t0) r3
            int r4 = r3.m
            r0 = -2147483648(0xffffffff80000000, float:-0.0)
            r1 = r4 & r0
            if (r1 == 0) goto L13
            int r4 = r4 - r0
            r3.m = r4
            goto L1a
        L13:
            androidx.compose.foundation.gestures.t0 r3 = new androidx.compose.foundation.gestures.t0
            kotlin.coroutines.jvm.internal.c r7 = (kotlin.coroutines.jvm.internal.c) r7
            r3.<init>(r2, r7)
        L1a:
            java.lang.Object r4 = r3.k
            kotlin.coroutines.intrinsics.a r7 = kotlin.coroutines.intrinsics.a.a
            int r0 = r3.m
            r1 = 1
            if (r0 == 0) goto L33
            if (r0 != r1) goto L2b
            long r5 = r3.j
            androidx.glance.appwidget.protobuf.Z.e(r4)
            goto L47
        L2b:
            java.lang.IllegalStateException r3 = new java.lang.IllegalStateException
            java.lang.String r4 = "call to 'resume' before 'invoke' with coroutine"
            r3.<init>(r4)
            throw r3
        L33:
            androidx.glance.appwidget.protobuf.Z.e(r4)
            boolean r4 = r2.b
            if (r4 == 0) goto L50
            r3.j = r5
            r3.m = r1
            androidx.compose.foundation.gestures.L0 r4 = r2.a
            java.lang.Object r4 = r4.b(r5, r3)
            if (r4 != r7) goto L47
            return r7
        L47:
            androidx.compose.ui.unit.o r4 = (androidx.compose.ui.unit.o) r4
            long r3 = r4.a
            long r3 = androidx.compose.ui.unit.o.d(r5, r3)
            goto L52
        L50:
            r3 = 0
        L52:
            androidx.compose.ui.unit.o r5 = new androidx.compose.ui.unit.o
            r5.<init>(r3)
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.gestures.C0353u0.p(long, long, kotlin.coroutines.h):java.lang.Object");
    }

    @Override // androidx.compose.ui.input.nestedscroll.a
    public final long s0(long j, long j2, int i) {
        if (!this.b) {
            return 0L;
        }
        L0 l0 = this.a;
        if (l0.a.a()) {
            return 0L;
        }
        return l0.g(l0.c(l0.a.e(l0.c(l0.f(j2)))));
    }
}
