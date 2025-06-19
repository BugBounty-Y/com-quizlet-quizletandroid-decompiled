package androidx.compose.foundation.gestures;

import androidx.compose.ui.node.AbstractC0910f;
import com.google.android.gms.internal.mlkit_vision_barcode.Q4;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class L0 {
    public E0 a;
    public androidx.compose.foundation.C0 b;
    public InterfaceC0314a0 c;
    public EnumC0320d0 d;
    public boolean e;
    public androidx.compose.ui.input.nestedscroll.e f;
    public int g = 1;
    public InterfaceC0334k0 h = AbstractC0349s0.a;
    public final I0 i = new I0(this);
    public final androidx.camera.lifecycle.f j = new androidx.camera.lifecycle.f(this, 13);

    public L0(E0 e0, androidx.compose.foundation.C0 c0, InterfaceC0314a0 interfaceC0314a0, EnumC0320d0 enumC0320d0, boolean z, androidx.compose.ui.input.nestedscroll.e eVar) {
        this.a = e0;
        this.b = c0;
        this.c = interfaceC0314a0;
        this.d = enumC0320d0;
        this.e = z;
        this.f = eVar;
    }

    public static final long a(L0 l0, InterfaceC0334k0 interfaceC0334k0, long j, int i) {
        androidx.compose.ui.input.nestedscroll.i iVar = l0.f.a;
        androidx.compose.ui.input.nestedscroll.i iVar2 = null;
        androidx.compose.ui.input.nestedscroll.i iVar3 = (iVar == null || !iVar.m) ? null : (androidx.compose.ui.input.nestedscroll.i) AbstractC0910f.k(iVar);
        long jL = iVar3 != null ? iVar3.L(i, j) : 0L;
        long jG = androidx.compose.ui.geometry.b.g(j, jL);
        long jD = l0.d(l0.g(interfaceC0334k0.a(l0.f(l0.d(androidx.compose.ui.geometry.b.a(DefinitionKt.NO_Float_VALUE, l0.d == EnumC0320d0.b ? 1 : 2, jG))))));
        long jG2 = androidx.compose.ui.geometry.b.g(jG, jD);
        androidx.compose.ui.input.nestedscroll.i iVar4 = l0.f.a;
        if (iVar4 != null && iVar4.m) {
            iVar2 = (androidx.compose.ui.input.nestedscroll.i) AbstractC0910f.k(iVar4);
        }
        androidx.compose.ui.input.nestedscroll.i iVar5 = iVar2;
        return androidx.compose.ui.geometry.b.h(androidx.compose.ui.geometry.b.h(jL, jD), iVar5 != null ? iVar5.s0(jD, jG2, i) : 0L);
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object b(long r11, kotlin.coroutines.jvm.internal.c r13) {
        /*
            r10 = this;
            boolean r0 = r13 instanceof androidx.compose.foundation.gestures.F0
            if (r0 == 0) goto L13
            r0 = r13
            androidx.compose.foundation.gestures.F0 r0 = (androidx.compose.foundation.gestures.F0) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            androidx.compose.foundation.gestures.F0 r0 = new androidx.compose.foundation.gestures.F0
            r0.<init>(r10, r13)
        L18:
            java.lang.Object r13 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            if (r2 == 0) goto L32
            if (r2 != r3) goto L2a
            kotlin.jvm.internal.I r11 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r13)
            r5 = r10
            goto L52
        L2a:
            java.lang.IllegalStateException r11 = new java.lang.IllegalStateException
            java.lang.String r12 = "call to 'resume' before 'invoke' with coroutine"
            r11.<init>(r12)
            throw r11
        L32:
            androidx.glance.appwidget.protobuf.Z.e(r13)
            kotlin.jvm.internal.I r6 = new kotlin.jvm.internal.I
            r6.<init>()
            r6.a = r11
            androidx.compose.foundation.u0 r13 = androidx.compose.foundation.u0.a
            androidx.compose.foundation.gestures.H0 r4 = new androidx.compose.foundation.gestures.H0
            r9 = 0
            r5 = r10
            r7 = r11
            r4.<init>(r5, r6, r7, r9)
            r0.j = r6
            r0.m = r3
            java.lang.Object r11 = r10.e(r13, r4, r0)
            if (r11 != r1) goto L51
            return r1
        L51:
            r11 = r6
        L52:
            long r11 = r11.a
            androidx.compose.ui.unit.o r13 = new androidx.compose.ui.unit.o
            r13.<init>(r11)
            return r13
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.gestures.L0.b(long, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public final float c(float f) {
        return this.e ? f * (-1) : f;
    }

    public final long d(long j) {
        return this.e ? androidx.compose.ui.geometry.b.i(j, -1.0f) : j;
    }

    public final Object e(androidx.compose.foundation.u0 u0Var, Function2 function2, kotlin.coroutines.jvm.internal.c cVar) {
        Object objC = this.a.c(u0Var, new K0(this, function2, null), cVar);
        return objC == kotlin.coroutines.intrinsics.a.a ? objC : Unit.a;
    }

    public final float f(long j) {
        return this.d == EnumC0320d0.b ? androidx.compose.ui.geometry.b.d(j) : androidx.compose.ui.geometry.b.e(j);
    }

    public final long g(float f) {
        if (f == DefinitionKt.NO_Float_VALUE) {
            return 0L;
        }
        return this.d == EnumC0320d0.b ? Q4.c(f, DefinitionKt.NO_Float_VALUE) : Q4.c(DefinitionKt.NO_Float_VALUE, f);
    }
}
