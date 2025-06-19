package androidx.compose.foundation;

/* renamed from: androidx.compose.foundation.f0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0310f0 extends androidx.compose.ui.p implements androidx.compose.ui.node.l0 {
    public androidx.compose.foundation.interaction.l n;
    public androidx.compose.foundation.interaction.h o;

    /* JADX WARN: Removed duplicated region for block: B:7:0x0016  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object M0(androidx.compose.foundation.C0310f0 r4, kotlin.coroutines.jvm.internal.c r5) {
        /*
            r4.getClass()
            boolean r0 = r5 instanceof androidx.compose.foundation.C0302b0
            if (r0 == 0) goto L16
            r0 = r5
            androidx.compose.foundation.b0 r0 = (androidx.compose.foundation.C0302b0) r0
            int r1 = r0.n
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L16
            int r1 = r1 - r2
            r0.n = r1
            goto L1b
        L16:
            androidx.compose.foundation.b0 r0 = new androidx.compose.foundation.b0
            r0.<init>(r4, r5)
        L1b:
            java.lang.Object r5 = r0.l
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.n
            r3 = 1
            if (r2 == 0) goto L38
            if (r2 != r3) goto L30
            androidx.compose.foundation.interaction.h r4 = r0.k
            androidx.compose.foundation.f0 r0 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r5)
            r5 = r4
            r4 = r0
            goto L53
        L30:
            java.lang.IllegalStateException r4 = new java.lang.IllegalStateException
            java.lang.String r5 = "call to 'resume' before 'invoke' with coroutine"
            r4.<init>(r5)
            throw r4
        L38:
            androidx.glance.appwidget.protobuf.Z.e(r5)
            androidx.compose.foundation.interaction.h r5 = r4.o
            if (r5 != 0) goto L55
            androidx.compose.foundation.interaction.h r5 = new androidx.compose.foundation.interaction.h
            r5.<init>()
            androidx.compose.foundation.interaction.l r2 = r4.n
            r0.j = r4
            r0.k = r5
            r0.n = r3
            java.lang.Object r0 = r2.c(r5, r0)
            if (r0 != r1) goto L53
            return r1
        L53:
            r4.o = r5
        L55:
            kotlin.Unit r4 = kotlin.Unit.a
            return r4
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.C0310f0.M0(androidx.compose.foundation.f0, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0016  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object N0(androidx.compose.foundation.C0310f0 r4, kotlin.coroutines.jvm.internal.c r5) {
        /*
            r4.getClass()
            boolean r0 = r5 instanceof androidx.compose.foundation.C0304c0
            if (r0 == 0) goto L16
            r0 = r5
            androidx.compose.foundation.c0 r0 = (androidx.compose.foundation.C0304c0) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L16
            int r1 = r1 - r2
            r0.m = r1
            goto L1b
        L16:
            androidx.compose.foundation.c0 r0 = new androidx.compose.foundation.c0
            r0.<init>(r4, r5)
        L1b:
            java.lang.Object r5 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            if (r2 == 0) goto L34
            if (r2 != r3) goto L2c
            androidx.compose.foundation.f0 r4 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r5)
            goto L4d
        L2c:
            java.lang.IllegalStateException r4 = new java.lang.IllegalStateException
            java.lang.String r5 = "call to 'resume' before 'invoke' with coroutine"
            r4.<init>(r5)
            throw r4
        L34:
            androidx.glance.appwidget.protobuf.Z.e(r5)
            androidx.compose.foundation.interaction.h r5 = r4.o
            if (r5 == 0) goto L50
            androidx.compose.foundation.interaction.i r2 = new androidx.compose.foundation.interaction.i
            r2.<init>(r5)
            androidx.compose.foundation.interaction.l r5 = r4.n
            r0.j = r4
            r0.m = r3
            java.lang.Object r5 = r5.c(r2, r0)
            if (r5 != r1) goto L4d
            return r1
        L4d:
            r5 = 0
            r4.o = r5
        L50:
            kotlin.Unit r4 = kotlin.Unit.a
            return r4
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.C0310f0.N0(androidx.compose.foundation.f0, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    @Override // androidx.compose.ui.node.l0
    public final void E(androidx.compose.ui.input.pointer.f fVar, androidx.compose.ui.input.pointer.g gVar, long j) {
        if (gVar == androidx.compose.ui.input.pointer.g.b) {
            int i = fVar.d;
            if (i == 4) {
                kotlinx.coroutines.E.A(A0(), null, null, new C0306d0(this, null), 3);
            } else if (i == 5) {
                kotlinx.coroutines.E.A(A0(), null, null, new C0308e0(this, null), 3);
            }
        }
    }

    @Override // androidx.compose.ui.node.l0
    public final void F() {
        O0();
    }

    @Override // androidx.compose.ui.p
    public final void F0() {
        O0();
    }

    public final void O0() {
        androidx.compose.foundation.interaction.h hVar = this.o;
        if (hVar != null) {
            this.n.a(new androidx.compose.foundation.interaction.i(hVar));
            this.o = null;
        }
    }
}
