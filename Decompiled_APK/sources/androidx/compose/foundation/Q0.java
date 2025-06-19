package androidx.compose.foundation;

import androidx.compose.foundation.gestures.EnumC0320d0;
import androidx.compose.ui.node.InterfaceC0926w;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class Q0 extends androidx.compose.ui.p implements InterfaceC0926w {
    public N0 n;
    public boolean o;

    @Override // androidx.compose.ui.node.InterfaceC0926w
    public final int b(androidx.compose.ui.node.O o, androidx.compose.ui.layout.J j, int i) {
        return this.o ? j.z(SubsamplingScaleImageView.TILE_SIZE_AUTO) : j.z(i);
    }

    @Override // androidx.compose.ui.node.InterfaceC0926w
    public final int c(androidx.compose.ui.node.O o, androidx.compose.ui.layout.J j, int i) {
        return this.o ? j.x(SubsamplingScaleImageView.TILE_SIZE_AUTO) : j.x(i);
    }

    @Override // androidx.compose.ui.node.InterfaceC0926w
    public final int f(androidx.compose.ui.node.O o, androidx.compose.ui.layout.J j, int i) {
        return this.o ? j.X(i) : j.X(SubsamplingScaleImageView.TILE_SIZE_AUTO);
    }

    @Override // androidx.compose.ui.node.InterfaceC0926w
    public final androidx.compose.ui.layout.L h(androidx.compose.ui.layout.M m, androidx.compose.ui.layout.J j, long j2) {
        AbstractC0460p.i(j2, this.o ? EnumC0320d0.a : EnumC0320d0.b);
        boolean z = this.o;
        int iH = SubsamplingScaleImageView.TILE_SIZE_AUTO;
        int iG = z ? Integer.MAX_VALUE : androidx.compose.ui.unit.a.g(j2);
        if (this.o) {
            iH = androidx.compose.ui.unit.a.h(j2);
        }
        androidx.compose.ui.layout.W wB = j.B(androidx.compose.ui.unit.a.a(j2, 0, iH, 0, iG, 5));
        int i = wB.a;
        int iH2 = androidx.compose.ui.unit.a.h(j2);
        if (i > iH2) {
            i = iH2;
        }
        int i2 = wB.b;
        int iG2 = androidx.compose.ui.unit.a.g(j2);
        if (i2 > iG2) {
            i2 = iG2;
        }
        int i3 = wB.b - i2;
        int i4 = wB.a - i;
        if (!this.o) {
            i3 = i4;
        }
        N0 n0 = this.n;
        n0.d.j(i3);
        androidx.compose.runtime.snapshots.h hVarD = androidx.compose.runtime.snapshots.r.d();
        Function1 function1E = hVarD != null ? hVarD.e() : null;
        androidx.compose.runtime.snapshots.h hVarE = androidx.compose.runtime.snapshots.r.e(hVarD);
        try {
            if (n0.g() > i3) {
                n0.a.j(i3);
            }
            Unit unit = Unit.a;
            androidx.compose.runtime.snapshots.r.g(hVarD, hVarE, function1E);
            this.n.b.j(this.o ? i2 : i);
            return m.n0(i, i2, kotlin.collections.V.c(), new P0(this, i3, wB, 0));
        } catch (Throwable th) {
            androidx.compose.runtime.snapshots.r.g(hVarD, hVarE, function1E);
            throw th;
        }
    }

    @Override // androidx.compose.ui.node.InterfaceC0926w
    public final int i(androidx.compose.ui.node.O o, androidx.compose.ui.layout.J j, int i) {
        return this.o ? j.b(i) : j.b(SubsamplingScaleImageView.TILE_SIZE_AUTO);
    }
}
