package androidx.compose.foundation.gestures;

import androidx.compose.ui.node.AbstractC0910f;
import androidx.compose.ui.node.InterfaceC0916l;
import androidx.compose.ui.node.InterfaceC0925v;
import com.google.android.gms.internal.mlkit_vision_barcode.Q4;
import com.google.android.gms.internal.mlkit_vision_barcode.R5;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.foundation.gestures.k, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0333k extends androidx.compose.ui.p implements InterfaceC0925v, InterfaceC0916l {
    public EnumC0320d0 n;
    public final L0 o;
    public boolean p;
    public InterfaceC0319d q;
    public androidx.compose.ui.layout.r s;
    public androidx.compose.ui.geometry.c t;
    public boolean u;
    public boolean w;
    public final com.google.firebase.platforminfo.c r = new com.google.firebase.platforminfo.c(8);
    public long v = 0;

    public C0333k(EnumC0320d0 enumC0320d0, L0 l0, boolean z, InterfaceC0319d interfaceC0319d) {
        this.n = enumC0320d0;
        this.o = l0;
        this.p = z;
        this.q = interfaceC0319d;
    }

    /* JADX WARN: Removed duplicated region for block: B:43:0x0073 A[EDGE_INSN: B:43:0x0073->B:25:0x0073 BREAK  A[LOOP:0: B:8:0x001c->B:45:?], SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:45:? A[LOOP:0: B:8:0x001c->B:45:?, LOOP_END, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final float M0(androidx.compose.foundation.gestures.C0333k r11, androidx.compose.foundation.gestures.InterfaceC0319d r12) {
        /*
            long r0 = r11.v
            r2 = 0
            boolean r0 = androidx.compose.ui.unit.j.a(r0, r2)
            if (r0 == 0) goto Lc
            goto L7f
        Lc:
            com.google.firebase.platforminfo.c r0 = r11.r
            java.lang.Object r0 = r0.a
            androidx.compose.runtime.collection.b r0 = (androidx.compose.runtime.collection.b) r0
            int r1 = r0.c
            r2 = 1
            r3 = 0
            if (r1 <= 0) goto L72
            int r1 = r1 - r2
            java.lang.Object[] r0 = r0.a
            r4 = r3
        L1c:
            r5 = r0[r1]
            androidx.compose.foundation.gestures.h r5 = (androidx.compose.foundation.gestures.C0327h) r5
            androidx.compose.foundation.relocation.f r5 = r5.a
            java.lang.Object r5 = r5.invoke()
            androidx.compose.ui.geometry.c r5 = (androidx.compose.ui.geometry.c) r5
            if (r5 == 0) goto L6d
            float r6 = r5.e()
            float r7 = r5.d()
            long r6 = com.google.android.gms.internal.mlkit_vision_barcode.T4.a(r6, r7)
            long r8 = r11.v
            long r8 = com.google.android.gms.internal.mlkit_vision_barcode.R5.f(r8)
            androidx.compose.foundation.gestures.d0 r10 = r11.n
            int r10 = r10.ordinal()
            if (r10 == 0) goto L59
            if (r10 != r2) goto L53
            float r6 = androidx.compose.ui.geometry.e.d(r6)
            float r7 = androidx.compose.ui.geometry.e.d(r8)
            int r6 = java.lang.Float.compare(r6, r7)
            goto L65
        L53:
            kotlin.NoWhenBranchMatchedException r11 = new kotlin.NoWhenBranchMatchedException
            r11.<init>()
            throw r11
        L59:
            float r6 = androidx.compose.ui.geometry.e.b(r6)
            float r7 = androidx.compose.ui.geometry.e.b(r8)
            int r6 = java.lang.Float.compare(r6, r7)
        L65:
            if (r6 > 0) goto L69
            r4 = r5
            goto L6d
        L69:
            if (r4 != 0) goto L73
            r4 = r5
            goto L73
        L6d:
            int r1 = r1 + (-1)
            if (r1 >= 0) goto L1c
            goto L73
        L72:
            r4 = r3
        L73:
            if (r4 != 0) goto L82
            boolean r0 = r11.u
            if (r0 == 0) goto L7d
            androidx.compose.ui.geometry.c r3 = r11.N0()
        L7d:
            if (r3 != 0) goto L81
        L7f:
            r11 = 0
            return r11
        L81:
            r4 = r3
        L82:
            long r0 = r11.v
            long r0 = com.google.android.gms.internal.mlkit_vision_barcode.R5.f(r0)
            androidx.compose.foundation.gestures.d0 r11 = r11.n
            int r11 = r11.ordinal()
            if (r11 == 0) goto La6
            if (r11 != r2) goto La0
            float r11 = r4.c
            float r2 = r4.a
            float r11 = r11 - r2
            float r0 = androidx.compose.ui.geometry.e.d(r0)
            float r11 = r12.a(r2, r11, r0)
            return r11
        La0:
            kotlin.NoWhenBranchMatchedException r11 = new kotlin.NoWhenBranchMatchedException
            r11.<init>()
            throw r11
        La6:
            float r11 = r4.d
            float r2 = r4.b
            float r11 = r11 - r2
            float r0 = androidx.compose.ui.geometry.e.b(r0)
            float r11 = r12.a(r2, r11, r0)
            return r11
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.gestures.C0333k.M0(androidx.compose.foundation.gestures.k, androidx.compose.foundation.gestures.d):float");
    }

    @Override // androidx.compose.ui.p
    public final boolean B0() {
        return false;
    }

    public final androidx.compose.ui.geometry.c N0() {
        if (this.m) {
            androidx.compose.ui.node.a0 a0VarU = AbstractC0910f.u(this);
            androidx.compose.ui.layout.r rVar = this.s;
            if (rVar != null) {
                if (!rVar.k()) {
                    rVar = null;
                }
                if (rVar != null) {
                    return a0VarU.o(rVar, false);
                }
            }
        }
        return null;
    }

    public final boolean O0(androidx.compose.ui.geometry.c cVar, long j) {
        long jQ0 = Q0(cVar, j);
        return Math.abs(androidx.compose.ui.geometry.b.d(jQ0)) <= 0.5f && Math.abs(androidx.compose.ui.geometry.b.e(jQ0)) <= 0.5f;
    }

    public final void P0() {
        InterfaceC0319d interfaceC0319d = this.q;
        if (interfaceC0319d == null) {
            interfaceC0319d = (InterfaceC0319d) AbstractC0910f.i(this, AbstractC0325g.a);
        }
        if (this.w) {
            throw new IllegalStateException("launchAnimation called when previous animation was running");
        }
        kotlinx.coroutines.E.A(A0(), null, kotlinx.coroutines.D.d, new C0331j(this, new o1(interfaceC0319d.b()), interfaceC0319d, null), 1);
    }

    public final long Q0(androidx.compose.ui.geometry.c cVar, long j) {
        long jF = R5.f(j);
        int iOrdinal = this.n.ordinal();
        if (iOrdinal == 0) {
            InterfaceC0319d interfaceC0319d = this.q;
            if (interfaceC0319d == null) {
                interfaceC0319d = (InterfaceC0319d) AbstractC0910f.i(this, AbstractC0325g.a);
            }
            float f = cVar.d;
            float f2 = cVar.b;
            return Q4.c(DefinitionKt.NO_Float_VALUE, interfaceC0319d.a(f2, f - f2, androidx.compose.ui.geometry.e.b(jF)));
        }
        if (iOrdinal != 1) {
            throw new NoWhenBranchMatchedException();
        }
        InterfaceC0319d interfaceC0319d2 = this.q;
        if (interfaceC0319d2 == null) {
            interfaceC0319d2 = (InterfaceC0319d) AbstractC0910f.i(this, AbstractC0325g.a);
        }
        float f3 = cVar.c;
        float f4 = cVar.a;
        return Q4.c(interfaceC0319d2.a(f4, f3 - f4, androidx.compose.ui.geometry.e.d(jF)), DefinitionKt.NO_Float_VALUE);
    }

    @Override // androidx.compose.ui.node.InterfaceC0925v
    public final void o(long j) {
        int iG;
        androidx.compose.ui.geometry.c cVarN0;
        long j2 = this.v;
        this.v = j;
        int iOrdinal = this.n.ordinal();
        if (iOrdinal == 0) {
            iG = Intrinsics.g((int) (j & 4294967295L), (int) (4294967295L & j2));
        } else {
            if (iOrdinal != 1) {
                throw new NoWhenBranchMatchedException();
            }
            iG = Intrinsics.g((int) (j >> 32), (int) (j2 >> 32));
        }
        if (iG < 0 && (cVarN0 = N0()) != null) {
            androidx.compose.ui.geometry.c cVar = this.t;
            if (cVar == null) {
                cVar = cVarN0;
            }
            if (!this.w && !this.u && O0(cVar, j2) && !O0(cVarN0, j)) {
                this.u = true;
                P0();
            }
            this.t = cVarN0;
        }
    }
}
