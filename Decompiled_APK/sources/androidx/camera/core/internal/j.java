package androidx.camera.core.internal;

import android.util.Rational;
import android.util.Size;
import androidx.camera.core.impl.InterfaceC0183w;
import androidx.camera.core.impl.P;
import com.google.android.gms.internal.measurement.T1;

/* loaded from: classes.dex */
public final class j {
    public final int a;
    public final int b;
    public final Rational c;
    public final boolean d;

    public j(InterfaceC0183w interfaceC0183w, Rational rational) {
        this.a = interfaceC0183w.a();
        this.b = interfaceC0183w.e();
        this.c = rational;
        boolean z = true;
        if (rational != null && rational.getNumerator() < rational.getDenominator()) {
            z = false;
        }
        this.d = z;
    }

    public final Size a(P p) {
        int iV = p.v();
        Size size = (Size) p.j(P.h0, null);
        if (size != null) {
            int iA = T1.a(T1.b(iV), this.a, 1 == this.b);
            if (iA == 90 || iA == 270) {
                return new Size(size.getHeight(), size.getWidth());
            }
        }
        return size;
    }
}
