package androidx.compose.foundation.gestures;

import androidx.compose.ui.node.AbstractC0918n;
import androidx.compose.ui.node.InterfaceC0916l;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public abstract class Q extends AbstractC0918n implements androidx.compose.ui.node.l0, InterfaceC0916l {
    public EnumC0320d0 p;
    public kotlin.jvm.internal.r q;
    public boolean r;
    public androidx.compose.foundation.interaction.l s;
    public kotlinx.coroutines.channels.h t;
    public androidx.compose.foundation.interaction.b u;
    public boolean v;
    public androidx.compose.ui.input.pointer.B w;

    /* JADX WARN: Multi-variable type inference failed */
    public Q(Function1 function1, boolean z, androidx.compose.foundation.interaction.l lVar, EnumC0320d0 enumC0320d0) {
        this.p = enumC0320d0;
        this.q = (kotlin.jvm.internal.r) function1;
        this.r = z;
        this.s = lVar;
        new androidx.camera.lifecycle.f(this, 11);
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0016  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object P0(androidx.compose.foundation.gestures.Q r5, kotlin.coroutines.jvm.internal.c r6) {
        /*
            r5.getClass()
            boolean r0 = r6 instanceof androidx.compose.foundation.gestures.L
            if (r0 == 0) goto L16
            r0 = r6
            androidx.compose.foundation.gestures.L r0 = (androidx.compose.foundation.gestures.L) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L16
            int r1 = r1 - r2
            r0.m = r1
            goto L1b
        L16:
            androidx.compose.foundation.gestures.L r0 = new androidx.compose.foundation.gestures.L
            r0.<init>(r5, r6)
        L1b:
            java.lang.Object r6 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            if (r2 == 0) goto L34
            if (r2 != r3) goto L2c
            androidx.compose.foundation.gestures.Q r5 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L4f
        L2c:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L34:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            androidx.compose.foundation.interaction.b r6 = r5.u
            if (r6 == 0) goto L52
            androidx.compose.foundation.interaction.l r2 = r5.s
            if (r2 == 0) goto L4f
            androidx.compose.foundation.interaction.a r4 = new androidx.compose.foundation.interaction.a
            r4.<init>(r6)
            r0.j = r5
            r0.m = r3
            java.lang.Object r6 = r2.c(r4, r0)
            if (r6 != r1) goto L4f
            return r1
        L4f:
            r6 = 0
            r5.u = r6
        L52:
            r0 = 0
            r5.V0(r0)
            kotlin.Unit r5 = kotlin.Unit.a
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.gestures.Q.P0(androidx.compose.foundation.gestures.Q, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0016  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object Q0(androidx.compose.foundation.gestures.Q r6, androidx.compose.foundation.gestures.C0356w r7, kotlin.coroutines.jvm.internal.c r8) {
        /*
            r6.getClass()
            boolean r0 = r8 instanceof androidx.compose.foundation.gestures.M
            if (r0 == 0) goto L16
            r0 = r8
            androidx.compose.foundation.gestures.M r0 = (androidx.compose.foundation.gestures.M) r0
            int r1 = r0.o
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L16
            int r1 = r1 - r2
            r0.o = r1
            goto L1b
        L16:
            androidx.compose.foundation.gestures.M r0 = new androidx.compose.foundation.gestures.M
            r0.<init>(r6, r8)
        L1b:
            java.lang.Object r8 = r0.m
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.o
            r3 = 2
            r4 = 1
            if (r2 == 0) goto L43
            if (r2 == r4) goto L3b
            if (r2 != r3) goto L33
            androidx.compose.foundation.interaction.b r6 = r0.l
            androidx.compose.foundation.gestures.w r7 = r0.k
            androidx.compose.foundation.gestures.Q r0 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L7a
        L33:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r7 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r7)
            throw r6
        L3b:
            androidx.compose.foundation.gestures.w r7 = r0.k
            androidx.compose.foundation.gestures.Q r6 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L60
        L43:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            androidx.compose.foundation.interaction.b r8 = r6.u
            if (r8 == 0) goto L60
            androidx.compose.foundation.interaction.l r2 = r6.s
            if (r2 == 0) goto L60
            androidx.compose.foundation.interaction.a r5 = new androidx.compose.foundation.interaction.a
            r5.<init>(r8)
            r0.j = r6
            r0.k = r7
            r0.o = r4
            java.lang.Object r8 = r2.c(r5, r0)
            if (r8 != r1) goto L60
            goto L77
        L60:
            androidx.compose.foundation.interaction.b r8 = new androidx.compose.foundation.interaction.b
            r8.<init>()
            androidx.compose.foundation.interaction.l r2 = r6.s
            if (r2 == 0) goto L7c
            r0.j = r6
            r0.k = r7
            r0.l = r8
            r0.o = r3
            java.lang.Object r0 = r2.c(r8, r0)
            if (r0 != r1) goto L78
        L77:
            return r1
        L78:
            r0 = r6
            r6 = r8
        L7a:
            r8 = r6
            r6 = r0
        L7c:
            r6.u = r8
            long r7 = r7.a
            r6.U0(r7)
            kotlin.Unit r6 = kotlin.Unit.a
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.gestures.Q.Q0(androidx.compose.foundation.gestures.Q, androidx.compose.foundation.gestures.w, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0016  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object R0(androidx.compose.foundation.gestures.Q r5, androidx.compose.foundation.gestures.C0358x r6, kotlin.coroutines.jvm.internal.c r7) {
        /*
            r5.getClass()
            boolean r0 = r7 instanceof androidx.compose.foundation.gestures.N
            if (r0 == 0) goto L16
            r0 = r7
            androidx.compose.foundation.gestures.N r0 = (androidx.compose.foundation.gestures.N) r0
            int r1 = r0.n
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L16
            int r1 = r1 - r2
            r0.n = r1
            goto L1b
        L16:
            androidx.compose.foundation.gestures.N r0 = new androidx.compose.foundation.gestures.N
            r0.<init>(r5, r7)
        L1b:
            java.lang.Object r7 = r0.l
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.n
            r3 = 1
            if (r2 == 0) goto L36
            if (r2 != r3) goto L2e
            androidx.compose.foundation.gestures.x r6 = r0.k
            androidx.compose.foundation.gestures.Q r5 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L53
        L2e:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L36:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            androidx.compose.foundation.interaction.b r7 = r5.u
            if (r7 == 0) goto L56
            androidx.compose.foundation.interaction.l r2 = r5.s
            if (r2 == 0) goto L53
            androidx.compose.foundation.interaction.c r4 = new androidx.compose.foundation.interaction.c
            r4.<init>(r7)
            r0.j = r5
            r0.k = r6
            r0.n = r3
            java.lang.Object r7 = r2.c(r4, r0)
            if (r7 != r1) goto L53
            return r1
        L53:
            r7 = 0
            r5.u = r7
        L56:
            long r6 = r6.a
            r5.V0(r6)
            kotlin.Unit r5 = kotlin.Unit.a
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.gestures.Q.R0(androidx.compose.foundation.gestures.Q, androidx.compose.foundation.gestures.x, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public void E(androidx.compose.ui.input.pointer.f fVar, androidx.compose.ui.input.pointer.g gVar, long j) {
        if (this.r && this.w == null) {
            K k = new K(this, null);
            androidx.compose.ui.input.pointer.f fVar2 = androidx.compose.ui.input.pointer.v.a;
            androidx.compose.ui.input.pointer.B b = new androidx.compose.ui.input.pointer.B(null, null, k);
            M0(b);
            this.w = b;
        }
        androidx.compose.ui.input.pointer.B b2 = this.w;
        if (b2 != null) {
            b2.E(fVar, gVar, j);
        }
    }

    @Override // androidx.compose.ui.node.l0
    public final void F() {
        androidx.compose.ui.input.pointer.B b = this.w;
        if (b != null) {
            b.F();
        }
    }

    @Override // androidx.compose.ui.p
    public final void F0() {
        this.v = false;
        S0();
    }

    public final void S0() {
        androidx.compose.foundation.interaction.b bVar = this.u;
        if (bVar != null) {
            androidx.compose.foundation.interaction.l lVar = this.s;
            if (lVar != null) {
                lVar.a(new androidx.compose.foundation.interaction.a(bVar));
            }
            this.u = null;
        }
    }

    public abstract Object T0(O o, P p);

    public abstract void U0(long j);

    public abstract void V0(long j);

    public abstract boolean W0();

    /* JADX WARN: Multi-variable type inference failed */
    public final void X0(Function1 function1, boolean z, androidx.compose.foundation.interaction.l lVar, EnumC0320d0 enumC0320d0, boolean z2) {
        androidx.compose.ui.input.pointer.B b;
        this.q = (kotlin.jvm.internal.r) function1;
        boolean z3 = true;
        if (this.r != z) {
            this.r = z;
            if (!z) {
                S0();
                androidx.compose.ui.input.pointer.B b2 = this.w;
                if (b2 != null) {
                    N0(b2);
                }
                this.w = null;
            }
            z2 = true;
        }
        if (!Intrinsics.b(this.s, lVar)) {
            S0();
            this.s = lVar;
        }
        if (this.p != enumC0320d0) {
            this.p = enumC0320d0;
        } else {
            z3 = z2;
        }
        if (!z3 || (b = this.w) == null) {
            return;
        }
        b.O0();
    }
}
