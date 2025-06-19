package androidx.compose.ui.node;

import androidx.compose.ui.layout.C0893n;
import com.google.android.gms.internal.mlkit_vision_barcode.W4;
import java.util.Map;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public abstract class O extends androidx.compose.ui.layout.W implements U, androidx.compose.ui.layout.M {
    public boolean f;
    public boolean g;
    public boolean h;
    public final androidx.compose.ui.layout.H i = new androidx.compose.ui.layout.H(this, 0);
    public androidx.collection.B j;
    public androidx.collection.B k;

    public static void I0(a0 a0Var) {
        F f;
        a0 a0Var2 = a0Var.m;
        E e = a0Var2 != null ? a0Var2.l : null;
        E e2 = a0Var.l;
        if (!Intrinsics.b(e, e2)) {
            e2.x.r.u.f();
            return;
        }
        InterfaceC0905a interfaceC0905aI = e2.x.r.i();
        if (interfaceC0905aI == null || (f = ((K) interfaceC0905aI).u) == null) {
            return;
        }
        f.f();
    }

    /* JADX WARN: Removed duplicated region for block: B:66:0x0102  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void A0(androidx.compose.ui.node.k0 r25) {
        /*
            Method dump skipped, instructions count: 267
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.node.O.A0(androidx.compose.ui.node.k0):void");
    }

    public abstract O B0();

    public abstract androidx.compose.ui.layout.r C0();

    public abstract boolean D0();

    public abstract E E0();

    public abstract androidx.compose.ui.layout.L F0();

    public abstract O G0();

    public abstract long H0();

    public abstract void J0();

    @Override // androidx.compose.ui.node.U
    public final void S(boolean z) {
        this.f = z;
    }

    @Override // androidx.compose.ui.layout.InterfaceC0894o
    public boolean a0() {
        return false;
    }

    @Override // androidx.compose.ui.layout.W
    public final int d0(C0893n c0893n) {
        int iY0;
        if (D0() && (iY0 = y0(c0893n)) != Integer.MIN_VALUE) {
            return iY0 + ((int) (this.e & 4294967295L));
        }
        return Integer.MIN_VALUE;
    }

    @Override // androidx.compose.ui.layout.M
    public final androidx.compose.ui.layout.L v(int i, int i2, Map map, Function1 function1) {
        if ((i & (-16777216)) == 0 && ((-16777216) & i2) == 0) {
            return new M(i, i2, map, function1, this);
        }
        W4.f("Size(" + i + " x " + i2 + ") is out of range. Each dimension must be between 0 and 16777215.");
        throw null;
    }

    public abstract int y0(C0893n c0893n);
}
