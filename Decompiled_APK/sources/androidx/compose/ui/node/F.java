package androidx.compose.ui.node;

import androidx.compose.runtime.C0775b0;
import androidx.compose.ui.layout.AbstractC0882c;
import androidx.compose.ui.layout.C0893n;
import com.google.android.gms.internal.mlkit_vision_barcode.Q4;
import java.util.HashMap;
import java.util.Map;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class F {
    public final androidx.compose.ui.layout.W a;
    public boolean c;
    public boolean d;
    public boolean e;
    public boolean f;
    public boolean g;
    public InterfaceC0905a h;
    public final /* synthetic */ int j;
    public boolean b = true;
    public final HashMap i = new HashMap();

    /* JADX WARN: Multi-variable type inference failed */
    public F(InterfaceC0905a interfaceC0905a, int i) {
        this.j = i;
        this.a = (androidx.compose.ui.layout.W) interfaceC0905a;
    }

    /* JADX WARN: Type inference failed for: r0v5, types: [kotlin.jvm.functions.Function2, kotlin.jvm.internal.o] */
    /* JADX WARN: Type inference failed for: r8v4, types: [androidx.compose.ui.layout.W, androidx.compose.ui.node.a] */
    public static final void a(F f, C0893n c0893n, int i, a0 a0Var) {
        f.getClass();
        float f2 = i;
        long jC = Q4.c(f2, f2);
        while (true) {
            switch (f.j) {
                case 0:
                    androidx.compose.ui.graphics.S s = a0.F;
                    jC = a0Var.o1(jC);
                    break;
                default:
                    P pU0 = a0Var.U0();
                    Intrinsics.d(pU0);
                    long j = pU0.m;
                    jC = androidx.compose.ui.geometry.b.h(Q4.c((int) (j >> 32), (int) (j & 4294967295L)), jC);
                    break;
            }
            a0Var = a0Var.n;
            Intrinsics.d(a0Var);
            if (a0Var.equals(f.a.e())) {
                int iRound = Math.round(c0893n instanceof C0893n ? androidx.compose.ui.geometry.b.e(jC) : androidx.compose.ui.geometry.b.d(jC));
                HashMap map = f.i;
                if (map.containsKey(c0893n)) {
                    int iIntValue = ((Number) kotlin.collections.V.d(c0893n, map)).intValue();
                    C0893n c0893n2 = AbstractC0882c.a;
                    iRound = ((Number) c0893n.a.invoke(Integer.valueOf(iIntValue), Integer.valueOf(iRound))).intValue();
                }
                map.put(c0893n, Integer.valueOf(iRound));
                return;
            }
            if (f.b(a0Var).containsKey(c0893n)) {
                float fC = f.c(a0Var, c0893n);
                jC = Q4.c(fC, fC);
            }
        }
    }

    public final Map b(a0 a0Var) {
        switch (this.j) {
            case 0:
                return a0Var.F0().c();
            default:
                P pU0 = a0Var.U0();
                Intrinsics.d(pU0);
                return pU0.F0().c();
        }
    }

    public final int c(a0 a0Var, C0893n c0893n) {
        switch (this.j) {
            case 0:
                return a0Var.d0(c0893n);
            default:
                P pU0 = a0Var.U0();
                Intrinsics.d(pU0);
                return pU0.d0(c0893n);
        }
    }

    public final boolean d() {
        return this.c || this.e || this.f || this.g;
    }

    public final boolean e() {
        h();
        return this.h != null;
    }

    /* JADX WARN: Type inference failed for: r0v1, types: [androidx.compose.ui.layout.W, androidx.compose.ui.node.a] */
    public final void f() {
        this.b = true;
        ?? r0 = this.a;
        InterfaceC0905a interfaceC0905aI = r0.i();
        if (interfaceC0905aI == null) {
            return;
        }
        if (this.c) {
            interfaceC0905aI.W();
        } else if (this.e || this.d) {
            interfaceC0905aI.requestLayout();
        }
        if (this.f) {
            r0.W();
        }
        if (this.g) {
            r0.requestLayout();
        }
        interfaceC0905aI.c().f();
    }

    /* JADX WARN: Type inference failed for: r2v1, types: [androidx.compose.ui.layout.W, androidx.compose.ui.node.a] */
    public final void g() {
        HashMap map = this.i;
        map.clear();
        C0775b0 c0775b0 = new C0775b0(this, 17);
        ?? r2 = this.a;
        r2.p(c0775b0);
        map.putAll(b(r2.e()));
        this.b = false;
    }

    /* JADX WARN: Removed duplicated region for block: B:13:0x0023  */
    /* JADX WARN: Type inference failed for: r1v0, types: [androidx.compose.ui.layout.W, androidx.compose.ui.node.a] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void h() {
        /*
            r2 = this;
            boolean r0 = r2.d()
            androidx.compose.ui.layout.W r1 = r2.a
            if (r0 == 0) goto L9
            goto L51
        L9:
            androidx.compose.ui.node.a r0 = r1.i()
            if (r0 != 0) goto L10
            goto L53
        L10:
            androidx.compose.ui.node.F r0 = r0.c()
            androidx.compose.ui.node.a r1 = r0.h
            if (r1 == 0) goto L23
            androidx.compose.ui.node.F r0 = r1.c()
            boolean r0 = r0.d()
            if (r0 == 0) goto L23
            goto L51
        L23:
            androidx.compose.ui.node.a r0 = r2.h
            if (r0 == 0) goto L53
            androidx.compose.ui.node.F r1 = r0.c()
            boolean r1 = r1.d()
            if (r1 == 0) goto L32
            goto L53
        L32:
            androidx.compose.ui.node.a r1 = r0.i()
            if (r1 == 0) goto L41
            androidx.compose.ui.node.F r1 = r1.c()
            if (r1 == 0) goto L41
            r1.h()
        L41:
            androidx.compose.ui.node.a r0 = r0.i()
            if (r0 == 0) goto L50
            androidx.compose.ui.node.F r0 = r0.c()
            if (r0 == 0) goto L50
            androidx.compose.ui.node.a r1 = r0.h
            goto L51
        L50:
            r1 = 0
        L51:
            r2.h = r1
        L53:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.node.F.h():void");
    }
}
