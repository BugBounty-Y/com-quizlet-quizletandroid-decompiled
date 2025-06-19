package androidx.compose.foundation.pager;

import androidx.compose.animation.core.InterfaceC0256n;
import androidx.compose.foundation.gestures.InterfaceC0319d;
import androidx.compose.runtime.L0;
import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes.dex */
public final class n implements InterfaceC0319d {
    public final C0466e b;
    public final InterfaceC0319d c;
    public final InterfaceC0256n d;

    public n(C0466e c0466e, InterfaceC0319d interfaceC0319d) {
        this.b = c0466e;
        this.c = interfaceC0319d;
        this.d = interfaceC0319d.b();
    }

    @Override // androidx.compose.foundation.gestures.InterfaceC0319d
    public final float a(float f, float f2, float f3) {
        float fA = this.c.a(f, f2, f3);
        C0466e c0466e = this.b;
        if (fA == DefinitionKt.NO_Float_VALUE) {
            int i = c0466e.e;
            if (i == 0) {
                return DefinitionKt.NO_Float_VALUE;
            }
            float fN = i * (-1.0f);
            if (((Boolean) ((L0) c0466e.F).getValue()).booleanValue()) {
                fN += c0466e.n();
            }
            return kotlin.ranges.l.b(fN, -f3, f3);
        }
        float fN2 = c0466e.e * (-1);
        while (fA > DefinitionKt.NO_Float_VALUE && fN2 < fA) {
            fN2 += c0466e.n();
        }
        while (fA < DefinitionKt.NO_Float_VALUE && fN2 > fA) {
            fN2 -= c0466e.n();
        }
        return fN2;
    }

    @Override // androidx.compose.foundation.gestures.InterfaceC0319d
    public final InterfaceC0256n b() {
        return this.d;
    }
}
