package androidx.compose.foundation.layout;

import androidx.compose.ui.layout.InterfaceC0894o;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class G0 implements androidx.compose.ui.layout.K, C0 {
    public final InterfaceC0388h a;
    public final androidx.compose.ui.h b;

    public G0(InterfaceC0388h interfaceC0388h, androidx.compose.ui.h hVar) {
        this.a = interfaceC0388h;
        this.b = hVar;
    }

    @Override // androidx.compose.foundation.layout.C0
    public final void a(int i, int[] iArr, int[] iArr2, androidx.compose.ui.layout.M m) {
        this.a.c(m, i, iArr, m.getLayoutDirection(), iArr2);
    }

    @Override // androidx.compose.foundation.layout.C0
    public final androidx.compose.ui.layout.L b(androidx.compose.ui.layout.W[] wArr, androidx.compose.ui.layout.M m, int i, int[] iArr, int i2, int i3, int[] iArr2, int i4, int i5, int i6) {
        return m.n0(i2, i3, kotlin.collections.V.c(), new F0(wArr, this, i3, i, iArr));
    }

    @Override // androidx.compose.foundation.layout.C0
    public final int c(androidx.compose.ui.layout.W w) {
        return w.a;
    }

    @Override // androidx.compose.foundation.layout.C0
    public final long d(boolean z, int i, int i2, int i3) {
        return E0.a(z, i, i2, i3);
    }

    @Override // androidx.compose.foundation.layout.C0
    public final int e(androidx.compose.ui.layout.W w) {
        return w.b;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof G0)) {
            return false;
        }
        G0 g0 = (G0) obj;
        return Intrinsics.b(this.a, g0.a) && Intrinsics.b(this.b, g0.b);
    }

    public final int hashCode() {
        return Float.hashCode(this.b.a) + (this.a.hashCode() * 31);
    }

    @Override // androidx.compose.ui.layout.K
    public final int maxIntrinsicHeight(InterfaceC0894o interfaceC0894o, List list, int i) {
        int iM0 = interfaceC0894o.m0(this.a.a());
        if (list.isEmpty()) {
            return 0;
        }
        int iMin = Math.min((list.size() - 1) * iM0, i);
        int size = list.size();
        int iMax = 0;
        float f = 0.0f;
        for (int i2 = 0; i2 < size; i2++) {
            androidx.compose.ui.layout.J j = (androidx.compose.ui.layout.J) list.get(i2);
            float fO = AbstractC0382e.o(AbstractC0382e.n(j));
            if (fO == DefinitionKt.NO_Float_VALUE) {
                int iMin2 = Math.min(j.z(SubsamplingScaleImageView.TILE_SIZE_AUTO), i == Integer.MAX_VALUE ? Integer.MAX_VALUE : i - iMin);
                iMin += iMin2;
                iMax = Math.max(iMax, j.b(iMin2));
            } else if (fO > DefinitionKt.NO_Float_VALUE) {
                f += fO;
            }
        }
        int iRound = f == DefinitionKt.NO_Float_VALUE ? 0 : i == Integer.MAX_VALUE ? Integer.MAX_VALUE : Math.round(Math.max(i - iMin, 0) / f);
        int size2 = list.size();
        for (int i3 = 0; i3 < size2; i3++) {
            androidx.compose.ui.layout.J j2 = (androidx.compose.ui.layout.J) list.get(i3);
            float fO2 = AbstractC0382e.o(AbstractC0382e.n(j2));
            if (fO2 > DefinitionKt.NO_Float_VALUE) {
                iMax = Math.max(iMax, j2.b(iRound != Integer.MAX_VALUE ? Math.round(iRound * fO2) : Integer.MAX_VALUE));
            }
        }
        return iMax;
    }

    @Override // androidx.compose.ui.layout.K
    public final int maxIntrinsicWidth(InterfaceC0894o interfaceC0894o, List list, int i) {
        int iM0 = interfaceC0894o.m0(this.a.a());
        if (list.isEmpty()) {
            return 0;
        }
        int size = list.size();
        int iMax = 0;
        int i2 = 0;
        float f = 0.0f;
        for (int i3 = 0; i3 < size; i3++) {
            androidx.compose.ui.layout.J j = (androidx.compose.ui.layout.J) list.get(i3);
            float fO = AbstractC0382e.o(AbstractC0382e.n(j));
            int iZ = j.z(i);
            if (fO == DefinitionKt.NO_Float_VALUE) {
                i2 += iZ;
            } else if (fO > DefinitionKt.NO_Float_VALUE) {
                f += fO;
                iMax = Math.max(iMax, Math.round(iZ / fO));
            }
        }
        return ((list.size() - 1) * iM0) + Math.round(iMax * f) + i2;
    }

    @Override // androidx.compose.ui.layout.K
    /* renamed from: measure-3p2s80s */
    public final androidx.compose.ui.layout.L mo1measure3p2s80s(androidx.compose.ui.layout.M m, List list, long j) {
        return AbstractC0382e.q(this, androidx.compose.ui.unit.a.j(j), androidx.compose.ui.unit.a.i(j), androidx.compose.ui.unit.a.h(j), androidx.compose.ui.unit.a.g(j), m.m0(this.a.a()), m, list, new androidx.compose.ui.layout.W[list.size()], 0, list.size(), null, 0);
    }

    @Override // androidx.compose.ui.layout.K
    public final int minIntrinsicHeight(InterfaceC0894o interfaceC0894o, List list, int i) {
        int iM0 = interfaceC0894o.m0(this.a.a());
        if (list.isEmpty()) {
            return 0;
        }
        int iMin = Math.min((list.size() - 1) * iM0, i);
        int size = list.size();
        int iMax = 0;
        float f = 0.0f;
        for (int i2 = 0; i2 < size; i2++) {
            androidx.compose.ui.layout.J j = (androidx.compose.ui.layout.J) list.get(i2);
            float fO = AbstractC0382e.o(AbstractC0382e.n(j));
            if (fO == DefinitionKt.NO_Float_VALUE) {
                int iMin2 = Math.min(j.z(SubsamplingScaleImageView.TILE_SIZE_AUTO), i == Integer.MAX_VALUE ? Integer.MAX_VALUE : i - iMin);
                iMin += iMin2;
                iMax = Math.max(iMax, j.X(iMin2));
            } else if (fO > DefinitionKt.NO_Float_VALUE) {
                f += fO;
            }
        }
        int iRound = f == DefinitionKt.NO_Float_VALUE ? 0 : i == Integer.MAX_VALUE ? Integer.MAX_VALUE : Math.round(Math.max(i - iMin, 0) / f);
        int size2 = list.size();
        for (int i3 = 0; i3 < size2; i3++) {
            androidx.compose.ui.layout.J j2 = (androidx.compose.ui.layout.J) list.get(i3);
            float fO2 = AbstractC0382e.o(AbstractC0382e.n(j2));
            if (fO2 > DefinitionKt.NO_Float_VALUE) {
                iMax = Math.max(iMax, j2.X(iRound != Integer.MAX_VALUE ? Math.round(iRound * fO2) : Integer.MAX_VALUE));
            }
        }
        return iMax;
    }

    @Override // androidx.compose.ui.layout.K
    public final int minIntrinsicWidth(InterfaceC0894o interfaceC0894o, List list, int i) {
        int iM0 = interfaceC0894o.m0(this.a.a());
        if (list.isEmpty()) {
            return 0;
        }
        int size = list.size();
        int iMax = 0;
        int i2 = 0;
        float f = 0.0f;
        for (int i3 = 0; i3 < size; i3++) {
            androidx.compose.ui.layout.J j = (androidx.compose.ui.layout.J) list.get(i3);
            float fO = AbstractC0382e.o(AbstractC0382e.n(j));
            int iX = j.x(i);
            if (fO == DefinitionKt.NO_Float_VALUE) {
                i2 += iX;
            } else if (fO > DefinitionKt.NO_Float_VALUE) {
                f += fO;
                iMax = Math.max(iMax, Math.round(iX / fO));
            }
        }
        return ((list.size() - 1) * iM0) + Math.round(iMax * f) + i2;
    }

    public final String toString() {
        return "RowMeasurePolicy(horizontalArrangement=" + this.a + ", verticalAlignment=" + this.b + ')';
    }
}
