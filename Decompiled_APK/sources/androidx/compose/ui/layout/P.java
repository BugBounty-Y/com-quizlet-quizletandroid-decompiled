package androidx.compose.ui.layout;

/* loaded from: classes.dex */
public final class P implements h0, InterfaceC0889j {
    public static final P b = new P(0);
    public final /* synthetic */ int a;

    public /* synthetic */ P(int i) {
        this.a = i;
    }

    @Override // androidx.compose.ui.layout.InterfaceC0889j
    public long a(long j, long j2) {
        switch (this.a) {
            case 1:
                float fMax = Math.max(androidx.compose.ui.geometry.e.d(j2) / androidx.compose.ui.geometry.e.d(j), androidx.compose.ui.geometry.e.b(j2) / androidx.compose.ui.geometry.e.b(j));
                return AbstractC0897s.b(fMax, fMax);
            case 2:
                return AbstractC0897s.b(androidx.compose.ui.geometry.e.d(j2) / androidx.compose.ui.geometry.e.d(j), androidx.compose.ui.geometry.e.b(j2) / androidx.compose.ui.geometry.e.b(j));
            case 3:
                float fB = androidx.compose.ui.geometry.e.b(j2) / androidx.compose.ui.geometry.e.b(j);
                return AbstractC0897s.b(fB, fB);
            case 4:
                float fD = androidx.compose.ui.geometry.e.d(j2) / androidx.compose.ui.geometry.e.d(j);
                return AbstractC0897s.b(fD, fD);
            case 5:
                float fMin = Math.min(androidx.compose.ui.geometry.e.d(j2) / androidx.compose.ui.geometry.e.d(j), androidx.compose.ui.geometry.e.b(j2) / androidx.compose.ui.geometry.e.b(j));
                return AbstractC0897s.b(fMin, fMin);
            default:
                if (androidx.compose.ui.geometry.e.d(j) <= androidx.compose.ui.geometry.e.d(j2) && androidx.compose.ui.geometry.e.b(j) <= androidx.compose.ui.geometry.e.b(j2)) {
                    return AbstractC0897s.b(1.0f, 1.0f);
                }
                float fMin2 = Math.min(androidx.compose.ui.geometry.e.d(j2) / androidx.compose.ui.geometry.e.d(j), androidx.compose.ui.geometry.e.b(j2) / androidx.compose.ui.geometry.e.b(j));
                return AbstractC0897s.b(fMin2, fMin2);
        }
    }

    @Override // androidx.compose.ui.layout.h0
    public void b(g0 g0Var) {
        g0Var.clear();
    }

    @Override // androidx.compose.ui.layout.h0
    public boolean c(Object obj, Object obj2) {
        return false;
    }

    public String toString() {
        switch (this.a) {
            case 7:
                return "ReusedSlotId";
            default:
                return super.toString();
        }
    }
}
