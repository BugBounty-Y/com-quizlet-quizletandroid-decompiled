package androidx.compose.foundation.text.selection;

import androidx.compose.foundation.text.C0492h0;
import androidx.compose.foundation.text.K0;
import androidx.compose.foundation.text.u0;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.L0;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3205m5;

/* loaded from: classes.dex */
public final class h0 implements u0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ i0 b;

    public /* synthetic */ h0(i0 i0Var, int i) {
        this.a = i;
        this.b = i0Var;
    }

    private final void e() {
    }

    private final void f() {
    }

    private final void g() {
    }

    private final void i() {
    }

    /* JADX WARN: Type inference failed for: r13v10, types: [kotlin.jvm.functions.Function1, kotlin.jvm.internal.r] */
    @Override // androidx.compose.foundation.text.u0
    public final void a(long j) {
        K0 k0D;
        i0 i0Var;
        long j2;
        K0 k0D2;
        K0 k0D3;
        switch (this.a) {
            case 0:
                i0 i0Var2 = this.b;
                long jA = H.a(i0Var2.k(true));
                C0492h0 c0492h0 = i0Var2.d;
                if (c0492h0 != null && (k0D = c0492h0.d()) != null) {
                    long jE = k0D.e(jA);
                    i0Var2.m = jE;
                    ((L0) i0Var2.q).setValue(new androidx.compose.ui.geometry.b(jE));
                    i0Var2.o = 0L;
                    ((L0) i0Var2.p).setValue(androidx.compose.foundation.text.U.a);
                    i0Var2.r(false);
                    break;
                }
                break;
            default:
                i0 i0Var3 = this.b;
                if (i0Var3.j()) {
                    InterfaceC0773a0 interfaceC0773a0 = i0Var3.p;
                    if (((androidx.compose.foundation.text.U) ((L0) interfaceC0773a0).getValue()) == null) {
                        ((L0) interfaceC0773a0).setValue(androidx.compose.foundation.text.U.c);
                        i0Var3.r = -1;
                        i0Var3.m();
                        C0492h0 c0492h02 = i0Var3.d;
                        if (c0492h02 == null || (k0D3 = c0492h02.d()) == null || !k0D3.c(j)) {
                            i0Var = i0Var3;
                            j2 = j;
                            C0492h0 c0492h03 = i0Var.d;
                            if (c0492h03 != null && (k0D2 = c0492h03.d()) != null) {
                                int iG = i0Var.b.g(k0D2.b(j2, true));
                                androidx.compose.ui.text.input.A aE = i0.e(i0Var.l().a, AbstractC3205m5.c(iG, iG));
                                i0Var.h(false);
                                androidx.compose.ui.hapticfeedback.a aVar = i0Var.i;
                                if (aVar != null) {
                                    ((androidx.compose.ui.hapticfeedback.b) aVar).a();
                                }
                                i0Var.c.invoke(aE);
                            }
                        } else if (i0Var3.l().a.a.length() != 0) {
                            i0Var3.h(false);
                            i0Var = i0Var3;
                            j2 = j;
                            i0Var.n = Integer.valueOf((int) (i0.c(i0Var3, androidx.compose.ui.text.input.A.a(i0Var3.l(), null, androidx.compose.ui.text.K.b, 5), j, true, false, C0537s.e, true) >> 32));
                        }
                        i0Var.p(androidx.compose.foundation.text.V.a);
                        i0Var.m = j2;
                        ((L0) i0Var.q).setValue(new androidx.compose.ui.geometry.b(j2));
                        i0Var.o = 0L;
                        break;
                    }
                }
                break;
        }
    }

    @Override // androidx.compose.foundation.text.u0
    public final void b() {
        switch (this.a) {
            case 0:
                i0 i0Var = this.b;
                i0.b(i0Var, null);
                i0.a(i0Var, null);
                break;
        }
    }

    @Override // androidx.compose.foundation.text.u0
    public final void c() {
        int i = this.a;
    }

    /* JADX WARN: Removed duplicated region for block: B:21:0x0091  */
    /* JADX WARN: Type inference failed for: r0v6, types: [kotlin.jvm.functions.Function1, kotlin.jvm.internal.r] */
    @Override // androidx.compose.foundation.text.u0
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void d(long r11) {
        /*
            Method dump skipped, instructions count: 334
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.text.selection.h0.d(long):void");
    }

    public void h() {
        i0 i0Var = this.b;
        i0.b(i0Var, null);
        ((L0) i0Var.q).setValue(null);
        i0Var.r(true);
        i0Var.n = null;
        boolean zB = androidx.compose.ui.text.K.b(i0Var.l().b);
        i0Var.p(zB ? androidx.compose.foundation.text.V.c : androidx.compose.foundation.text.V.b);
        C0492h0 c0492h0 = i0Var.d;
        if (c0492h0 != null) {
            ((L0) c0492h0.m).setValue(Boolean.valueOf(!zB && W.w(i0Var, true)));
        }
        C0492h0 c0492h02 = i0Var.d;
        if (c0492h02 != null) {
            ((L0) c0492h02.n).setValue(Boolean.valueOf(!zB && W.w(i0Var, false)));
        }
        C0492h0 c0492h03 = i0Var.d;
        if (c0492h03 == null) {
            return;
        }
        ((L0) c0492h03.o).setValue(Boolean.valueOf(zB && W.w(i0Var, true)));
    }

    @Override // androidx.compose.foundation.text.u0
    public final void onCancel() {
        switch (this.a) {
            case 0:
                break;
            default:
                h();
                break;
        }
    }

    @Override // androidx.compose.foundation.text.u0
    public final void onStop() {
        switch (this.a) {
            case 0:
                i0 i0Var = this.b;
                i0.b(i0Var, null);
                i0.a(i0Var, null);
                break;
            default:
                h();
                break;
        }
    }
}
