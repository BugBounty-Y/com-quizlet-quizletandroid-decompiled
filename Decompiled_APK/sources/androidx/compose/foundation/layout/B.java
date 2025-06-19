package androidx.compose.foundation.layout;

import androidx.compose.ui.layout.InterfaceC0894o;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class B implements androidx.compose.ui.layout.K, C0 {
    public final InterfaceC0394k a;
    public final androidx.compose.ui.g b;

    public B(InterfaceC0394k interfaceC0394k, androidx.compose.ui.g gVar) {
        this.a = interfaceC0394k;
        this.b = gVar;
    }

    @Override // androidx.compose.foundation.layout.C0
    public final void a(int i, int[] iArr, int[] iArr2, androidx.compose.ui.layout.M m) {
        this.a.b(m, i, iArr, iArr2);
    }

    @Override // androidx.compose.foundation.layout.C0
    public final androidx.compose.ui.layout.L b(androidx.compose.ui.layout.W[] wArr, androidx.compose.ui.layout.M m, int i, int[] iArr, int i2, int i3, int[] iArr2, int i4, int i5, int i6) {
        return m.n0(i3, i2, kotlin.collections.V.c(), new C0411t(wArr, this, i3, i, m, iArr));
    }

    @Override // androidx.compose.foundation.layout.C0
    public final int c(androidx.compose.ui.layout.W w) {
        return w.b;
    }

    @Override // androidx.compose.foundation.layout.C0
    public final long d(boolean z, int i, int i2, int i3) {
        return A.b(z, i, i2, i3);
    }

    @Override // androidx.compose.foundation.layout.C0
    public final int e(androidx.compose.ui.layout.W w) {
        return w.a;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof B)) {
            return false;
        }
        B b = (B) obj;
        return Intrinsics.b(this.a, b.a) && this.b.equals(b.b);
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
        int size = list.size();
        int iMax = 0;
        int i2 = 0;
        float f = 0.0f;
        for (int i3 = 0; i3 < size; i3++) {
            androidx.compose.ui.layout.J j = (androidx.compose.ui.layout.J) list.get(i3);
            float fO = AbstractC0382e.o(AbstractC0382e.n(j));
            int iB = j.b(i);
            if (fO == DefinitionKt.NO_Float_VALUE) {
                i2 += iB;
            } else if (fO > DefinitionKt.NO_Float_VALUE) {
                f += fO;
                iMax = Math.max(iMax, Math.round(iB / fO));
            }
        }
        return ((list.size() - 1) * iM0) + Math.round(iMax * f) + i2;
    }

    @Override // androidx.compose.ui.layout.K
    public final int maxIntrinsicWidth(InterfaceC0894o interfaceC0894o, List list, int i) {
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
                int iMin2 = Math.min(j.b(SubsamplingScaleImageView.TILE_SIZE_AUTO), i == Integer.MAX_VALUE ? Integer.MAX_VALUE : i - iMin);
                iMin += iMin2;
                iMax = Math.max(iMax, j.z(iMin2));
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
                iMax = Math.max(iMax, j2.z(iRound != Integer.MAX_VALUE ? Math.round(iRound * fO2) : Integer.MAX_VALUE));
            }
        }
        return iMax;
    }

    @Override // androidx.compose.ui.layout.K
    /* renamed from: measure-3p2s80s */
    public final androidx.compose.ui.layout.L mo1measure3p2s80s(androidx.compose.ui.layout.M m, List list, long j) {
        return AbstractC0382e.q(this, androidx.compose.ui.unit.a.i(j), androidx.compose.ui.unit.a.j(j), androidx.compose.ui.unit.a.g(j), androidx.compose.ui.unit.a.h(j), m.m0(this.a.a()), m, list, new androidx.compose.ui.layout.W[list.size()], 0, list.size(), null, 0);
    }

    @Override // androidx.compose.ui.layout.K
    public final int minIntrinsicHeight(InterfaceC0894o interfaceC0894o, List list, int i) {
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
            int iX = j.X(i);
            if (fO == DefinitionKt.NO_Float_VALUE) {
                i2 += iX;
            } else if (fO > DefinitionKt.NO_Float_VALUE) {
                f += fO;
                iMax = Math.max(iMax, Math.round(iX / fO));
            }
        }
        return ((list.size() - 1) * iM0) + Math.round(iMax * f) + i2;
    }

    @Override // androidx.compose.ui.layout.K
    public final int minIntrinsicWidth(InterfaceC0894o interfaceC0894o, List list, int i) {
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
                int iMin2 = Math.min(j.b(SubsamplingScaleImageView.TILE_SIZE_AUTO), i == Integer.MAX_VALUE ? Integer.MAX_VALUE : i - iMin);
                iMin += iMin2;
                iMax = Math.max(iMax, j.x(iMin2));
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
                iMax = Math.max(iMax, j2.x(iRound != Integer.MAX_VALUE ? Math.round(iRound * fO2) : Integer.MAX_VALUE));
            }
        }
        return iMax;
    }

    public final String toString() {
        return "ColumnMeasurePolicy(verticalArrangement=" + this.a + ", horizontalAlignment=" + this.b + ')';
    }
}
