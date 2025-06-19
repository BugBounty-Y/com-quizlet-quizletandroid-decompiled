package androidx.compose.material3;

import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.NoWhenBranchMatchedException;

/* loaded from: classes.dex */
public abstract class B3 {
    public static final androidx.compose.runtime.X0 a = new androidx.compose.runtime.X0(C0584a0.q);

    public static final androidx.compose.ui.graphics.V a(InterfaceC0806l interfaceC0806l, int i) {
        A3 a3 = (A3) ((C0814p) interfaceC0806l).j(a);
        switch (AbstractC0147y.k(i)) {
            case 0:
                return a3.e;
            case 1:
                return b(a3.e);
            case 2:
                return a3.a;
            case 3:
                return b(a3.a);
            case 4:
                return androidx.compose.foundation.shape.e.a;
            case 5:
                return a3.d;
            case 6:
                float f = (float) 0.0d;
                return androidx.compose.foundation.shape.d.a(a3.d, new androidx.compose.foundation.shape.b(f), null, new androidx.compose.foundation.shape.b(f), 6);
            case 7:
                return b(a3.d);
            case 8:
                return a3.c;
            case 9:
                return androidx.compose.ui.graphics.F.a;
            case 10:
                return a3.b;
            default:
                throw new NoWhenBranchMatchedException();
        }
    }

    public static final androidx.compose.foundation.shape.d b(androidx.compose.foundation.shape.d dVar) {
        float f = (float) 0.0d;
        return androidx.compose.foundation.shape.d.a(dVar, null, new androidx.compose.foundation.shape.b(f), new androidx.compose.foundation.shape.b(f), 3);
    }
}
