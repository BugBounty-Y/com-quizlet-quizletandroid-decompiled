package androidx.compose.material3.pulltorefresh;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.F0;
import androidx.compose.ui.node.AbstractC0910f;
import androidx.compose.ui.node.AbstractC0918n;
import androidx.compose.ui.node.InterfaceC0916l;
import androidx.compose.ui.platform.AbstractC0955m0;
import com.google.android.gms.internal.mlkit_vision_barcode.Q4;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.functions.Function0;
import kotlinx.coroutines.E;

/* loaded from: classes.dex */
public final class o extends AbstractC0918n implements InterfaceC0916l, androidx.compose.ui.input.nestedscroll.a {
    public boolean p;
    public Function0 q;
    public q s;
    public float t;
    public boolean r = true;
    public final androidx.compose.ui.input.nestedscroll.i u = new androidx.compose.ui.input.nestedscroll.i(this, null);
    public final F0 v = C0776c.v(DefinitionKt.NO_Float_VALUE);
    public final F0 w = C0776c.v(DefinitionKt.NO_Float_VALUE);

    public o(boolean z, Function0 function0, q qVar, float f) {
        this.p = z;
        this.q = function0;
        this.s = qVar;
        this.t = f;
    }

    @Override // androidx.compose.ui.p
    public final void E0() {
        M0(this.u);
        E.A(A0(), null, null, new j(this, null), 3);
    }

    @Override // androidx.compose.ui.input.nestedscroll.a
    public final long L(int i, long j) {
        if (!this.s.a.e() && this.r && i == 1 && androidx.compose.ui.geometry.b.e(j) < DefinitionKt.NO_Float_VALUE) {
            return R0(j);
        }
        return 0L;
    }

    /* JADX WARN: Removed duplicated region for block: B:8:0x0014  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object P0(kotlin.coroutines.jvm.internal.c r9) {
        /*
            r8 = this;
            boolean r0 = r9 instanceof androidx.compose.material3.pulltorefresh.h
            if (r0 == 0) goto L14
            r0 = r9
            androidx.compose.material3.pulltorefresh.h r0 = (androidx.compose.material3.pulltorefresh.h) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L14
            int r1 = r1 - r2
            r0.m = r1
        L12:
            r5 = r0
            goto L1a
        L14:
            androidx.compose.material3.pulltorefresh.h r0 = new androidx.compose.material3.pulltorefresh.h
            r0.<init>(r8, r9)
            goto L12
        L1a:
            java.lang.Object r9 = r5.k
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r5.m
            r2 = 1
            r7 = 0
            if (r1 == 0) goto L34
            if (r1 != r2) goto L2c
            androidx.compose.material3.pulltorefresh.o r0 = r5.j
            androidx.glance.appwidget.protobuf.Z.e(r9)
            goto L58
        L2c:
            java.lang.IllegalStateException r9 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r9.<init>(r0)
            throw r9
        L34:
            androidx.glance.appwidget.protobuf.Z.e(r9)
            androidx.compose.material3.pulltorefresh.q r9 = r8.s
            r5.j = r8
            r5.m = r2
            r9.getClass()
            java.lang.Float r2 = new java.lang.Float
            r2.<init>(r7)
            androidx.compose.animation.core.e r1 = r9.a
            r3 = 0
            r6 = 14
            r4 = 0
            java.lang.Object r9 = androidx.compose.animation.core.C0238e.c(r1, r2, r3, r4, r5, r6)
            if (r9 != r0) goto L52
            goto L54
        L52:
            kotlin.Unit r9 = kotlin.Unit.a
        L54:
            if (r9 != r0) goto L57
            return r0
        L57:
            r0 = r8
        L58:
            androidx.compose.runtime.F0 r9 = r0.w
            r9.j(r7)
            androidx.compose.runtime.F0 r9 = r0.v
            r9.j(r7)
            kotlin.Unit r9 = kotlin.Unit.a
            return r9
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.material3.pulltorefresh.o.P0(kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:8:0x0014  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object Q0(kotlin.coroutines.jvm.internal.c r8) {
        /*
            r7 = this;
            boolean r0 = r8 instanceof androidx.compose.material3.pulltorefresh.i
            if (r0 == 0) goto L14
            r0 = r8
            androidx.compose.material3.pulltorefresh.i r0 = (androidx.compose.material3.pulltorefresh.i) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L14
            int r1 = r1 - r2
            r0.m = r1
        L12:
            r5 = r0
            goto L1a
        L14:
            androidx.compose.material3.pulltorefresh.i r0 = new androidx.compose.material3.pulltorefresh.i
            r0.<init>(r7, r8)
            goto L12
        L1a:
            java.lang.Object r8 = r5.k
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r5.m
            r2 = 1
            if (r1 == 0) goto L33
            if (r1 != r2) goto L2b
            androidx.compose.material3.pulltorefresh.o r0 = r5.j
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L59
        L2b:
            java.lang.IllegalStateException r8 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r8.<init>(r0)
            throw r8
        L33:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            androidx.compose.material3.pulltorefresh.q r8 = r7.s
            r5.j = r7
            r5.m = r2
            r8.getClass()
            java.lang.Float r2 = new java.lang.Float
            r1 = 1065353216(0x3f800000, float:1.0)
            r2.<init>(r1)
            androidx.compose.animation.core.e r1 = r8.a
            r3 = 0
            r6 = 14
            r4 = 0
            java.lang.Object r8 = androidx.compose.animation.core.C0238e.c(r1, r2, r3, r4, r5, r6)
            if (r8 != r0) goto L53
            goto L55
        L53:
            kotlin.Unit r8 = kotlin.Unit.a
        L55:
            if (r8 != r0) goto L58
            return r0
        L58:
            r0 = r7
        L59:
            int r8 = r0.S0()
            float r8 = (float) r8
            androidx.compose.runtime.F0 r1 = r0.w
            r1.j(r8)
            int r8 = r0.S0()
            float r8 = (float) r8
            androidx.compose.runtime.F0 r0 = r0.v
            r0.j(r8)
            kotlin.Unit r8 = kotlin.Unit.a
            return r8
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.material3.pulltorefresh.o.Q0(kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public final long R0(long j) {
        float fI;
        float fS0;
        if (this.p) {
            fI = 0.0f;
        } else {
            F0 f0 = this.w;
            float fE = androidx.compose.ui.geometry.b.e(j) + f0.i();
            if (fE < DefinitionKt.NO_Float_VALUE) {
                fE = 0.0f;
            }
            fI = fE - f0.i();
            f0.j(fE);
            if (f0.i() * 0.5f <= S0()) {
                fS0 = f0.i() * 0.5f;
            } else {
                float fB = kotlin.ranges.l.b(Math.abs((f0.i() * 0.5f) / S0()) - 1.0f, DefinitionKt.NO_Float_VALUE, 2.0f);
                fS0 = S0() + (S0() * (fB - (((float) Math.pow(fB, 2)) / 4)));
            }
            this.v.j(fS0);
        }
        return Q4.c(DefinitionKt.NO_Float_VALUE, fI);
    }

    public final int S0() {
        return ((androidx.compose.ui.unit.b) AbstractC0910f.i(this, AbstractC0955m0.f)).m0(this.t);
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object T0(float r7, kotlin.coroutines.jvm.internal.c r8) {
        /*
            r6 = this;
            boolean r0 = r8 instanceof androidx.compose.material3.pulltorefresh.m
            if (r0 == 0) goto L13
            r0 = r8
            androidx.compose.material3.pulltorefresh.m r0 = (androidx.compose.material3.pulltorefresh.m) r0
            int r1 = r0.n
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.n = r1
            goto L18
        L13:
            androidx.compose.material3.pulltorefresh.m r0 = new androidx.compose.material3.pulltorefresh.m
            r0.<init>(r6, r8)
        L18:
            java.lang.Object r8 = r0.l
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.n
            r3 = 2
            r4 = 1
            r5 = 0
            if (r2 == 0) goto L3f
            if (r2 == r4) goto L37
            if (r2 != r3) goto L2f
            float r7 = r0.k
            androidx.compose.material3.pulltorefresh.o r0 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L80
        L2f:
            java.lang.IllegalStateException r7 = new java.lang.IllegalStateException
            java.lang.String r8 = "call to 'resume' before 'invoke' with coroutine"
            r7.<init>(r8)
            throw r7
        L37:
            float r7 = r0.k
            androidx.compose.material3.pulltorefresh.o r0 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L6c
        L3f:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            boolean r8 = r6.p
            if (r8 == 0) goto L4c
            java.lang.Float r7 = new java.lang.Float
            r7.<init>(r5)
            return r7
        L4c:
            androidx.compose.runtime.F0 r8 = r6.w
            float r8 = r8.i()
            r2 = 1056964608(0x3f000000, float:0.5)
            float r8 = r8 * r2
            int r2 = r6.S0()
            float r2 = (float) r2
            int r8 = (r8 > r2 ? 1 : (r8 == r2 ? 0 : -1))
            if (r8 <= 0) goto L72
            r0.j = r6
            r0.k = r7
            r0.n = r4
            java.lang.Object r8 = r6.Q0(r0)
            if (r8 != r1) goto L6b
            goto L7e
        L6b:
            r0 = r6
        L6c:
            kotlin.jvm.functions.Function0 r8 = r0.q
            r8.invoke()
            goto L80
        L72:
            r0.j = r6
            r0.k = r7
            r0.n = r3
            java.lang.Object r8 = r6.P0(r0)
            if (r8 != r1) goto L7f
        L7e:
            return r1
        L7f:
            r0 = r6
        L80:
            androidx.compose.runtime.F0 r8 = r0.w
            float r8 = r8.i()
            int r8 = (r8 > r5 ? 1 : (r8 == r5 ? 0 : -1))
            if (r8 != 0) goto L8c
        L8a:
            r7 = r5
            goto L91
        L8c:
            int r8 = (r7 > r5 ? 1 : (r7 == r5 ? 0 : -1))
            if (r8 >= 0) goto L91
            goto L8a
        L91:
            androidx.compose.runtime.F0 r8 = r0.w
            r8.j(r5)
            java.lang.Float r8 = new java.lang.Float
            r8.<init>(r7)
            return r8
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.material3.pulltorefresh.o.T0(float, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    @Override // androidx.compose.ui.input.nestedscroll.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object i0(long r5, kotlin.coroutines.h r7) {
        /*
            r4 = this;
            boolean r0 = r7 instanceof androidx.compose.material3.pulltorefresh.l
            if (r0 == 0) goto L13
            r0 = r7
            androidx.compose.material3.pulltorefresh.l r0 = (androidx.compose.material3.pulltorefresh.l) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L1a
        L13:
            androidx.compose.material3.pulltorefresh.l r0 = new androidx.compose.material3.pulltorefresh.l
            kotlin.coroutines.jvm.internal.c r7 = (kotlin.coroutines.jvm.internal.c) r7
            r0.<init>(r4, r7)
        L1a:
            java.lang.Object r7 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L31
            if (r2 != r3) goto L29
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L41
        L29:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L31:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            float r5 = androidx.compose.ui.unit.o.c(r5)
            r0.l = r3
            java.lang.Object r7 = r4.T0(r5, r0)
            if (r7 != r1) goto L41
            return r1
        L41:
            java.lang.Number r7 = (java.lang.Number) r7
            float r5 = r7.floatValue()
            r6 = 0
            long r5 = com.google.android.gms.internal.mlkit_vision_barcode.T5.b(r6, r5)
            androidx.compose.ui.unit.o r7 = new androidx.compose.ui.unit.o
            r7.<init>(r5)
            return r7
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.material3.pulltorefresh.o.i0(long, kotlin.coroutines.h):java.lang.Object");
    }

    @Override // androidx.compose.ui.input.nestedscroll.a
    public final long s0(long j, long j2, int i) {
        if (this.s.a.e() || !this.r || i != 1) {
            return 0L;
        }
        long jR0 = R0(j2);
        E.A(A0(), null, null, new k(this, null), 3);
        return jR0;
    }
}
