package androidx.compose.ui.layout;

import com.google.android.gms.internal.mlkit_vision_barcode.P5;
import com.google.android.gms.internal.mlkit_vision_barcode.R5;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public abstract class W {
    public int a;
    public int b;
    public long c = R5.a(0, 0);
    public long d = Y.a;
    public long e = 0;

    public Object G() {
        return null;
    }

    public abstract int d0(C0893n c0893n);

    public int i0() {
        return (int) (this.c & 4294967295L);
    }

    public int k0() {
        return (int) (this.c >> 32);
    }

    public final void p0() {
        this.a = kotlin.ranges.l.c((int) (this.c >> 32), androidx.compose.ui.unit.a.j(this.d), androidx.compose.ui.unit.a.h(this.d));
        int iC = kotlin.ranges.l.c((int) (this.c & 4294967295L), androidx.compose.ui.unit.a.i(this.d), androidx.compose.ui.unit.a.g(this.d));
        this.b = iC;
        int i = this.a;
        long j = this.c;
        this.e = P5.b((i - ((int) (j >> 32))) / 2, (iC - ((int) (j & 4294967295L))) / 2);
    }

    public void r0(long j, float f, androidx.compose.ui.graphics.layer.b bVar) {
        s0(j, f, null);
    }

    public abstract void s0(long j, float f, Function1 function1);

    public final void t0(long j) {
        if (androidx.compose.ui.unit.j.a(this.c, j)) {
            return;
        }
        this.c = j;
        p0();
    }

    public final void x0(long j) {
        if (androidx.compose.ui.unit.a.b(this.d, j)) {
            return;
        }
        this.d = j;
        p0();
    }
}
