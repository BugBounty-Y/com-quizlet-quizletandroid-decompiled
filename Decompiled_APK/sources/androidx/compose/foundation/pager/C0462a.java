package androidx.compose.foundation.pager;

import androidx.camera.camera2.internal.p0;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.concurrent.CancellationException;

/* renamed from: androidx.compose.foundation.pager.a, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0462a implements androidx.compose.ui.input.nestedscroll.a {
    public final C0466e a;

    public C0462a(C0466e c0466e) {
        this.a = c0466e;
    }

    @Override // androidx.compose.ui.input.nestedscroll.a
    public final long L(int i, long j) {
        if (i != 1) {
            return 0L;
        }
        C0466e c0466e = this.a;
        if (Math.abs(c0466e.c.j()) <= 1.0E-6d) {
            return 0L;
        }
        p0 p0Var = c0466e.c;
        float fJ = p0Var.j() * c0466e.m();
        float f = ((c0466e.k().b + c0466e.k().c) * (-Math.signum(p0Var.j()))) + fJ;
        if (p0Var.j() > DefinitionKt.NO_Float_VALUE) {
            f = fJ;
            fJ = f;
        }
        float f2 = -c0466e.j.e(-kotlin.ranges.l.b(androidx.compose.ui.geometry.b.d(j), fJ, f));
        float fE = androidx.compose.ui.geometry.b.e(j);
        return (Float.floatToRawIntBits(fE) & 4294967295L) | (Float.floatToRawIntBits(f2) << 32);
    }

    @Override // androidx.compose.ui.input.nestedscroll.a
    public final Object p(long j, long j2, kotlin.coroutines.h hVar) {
        return new androidx.compose.ui.unit.o(androidx.compose.ui.unit.o.a(j2, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 1));
    }

    @Override // androidx.compose.ui.input.nestedscroll.a
    public final long s0(long j, long j2, int i) {
        if (i != 2 || androidx.compose.ui.geometry.b.d(j2) == DefinitionKt.NO_Float_VALUE) {
            return 0L;
        }
        throw new CancellationException("Scroll cancelled");
    }
}
