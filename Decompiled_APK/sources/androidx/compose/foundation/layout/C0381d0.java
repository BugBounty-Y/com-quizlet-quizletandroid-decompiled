package androidx.compose.foundation.layout;

import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.collection.C0212j;
import kotlin.NoWhenBranchMatchedException;

/* renamed from: androidx.compose.foundation.layout.d0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0381d0 {
    public int a;
    public androidx.compose.ui.layout.J b;
    public androidx.compose.ui.layout.W c;
    public androidx.compose.ui.layout.J d;
    public androidx.compose.ui.layout.W e;
    public C0212j f;
    public C0212j g;
    public C0389h0 h;

    public final C0212j a(int i, int i2, boolean z) {
        int iK = AbstractC0147y.k(2);
        if (iK == 0 || iK == 1) {
            return null;
        }
        if (iK == 2) {
            if (z) {
                return this.f;
            }
            return null;
        }
        if (iK != 3) {
            throw new NoWhenBranchMatchedException();
        }
        if (z) {
            return this.f;
        }
        if (i + 1 < 0 || i2 < 0) {
            return null;
        }
        return this.g;
    }

    public final void b(InterfaceC0387g0 interfaceC0387g0, androidx.compose.ui.layout.J j, androidx.compose.ui.layout.J j2, long j3) {
        int i = interfaceC0387g0.i() ? 1 : 2;
        long jZ = AbstractC0382e.z(i, AbstractC0382e.m(10, AbstractC0382e.l(i, j3)));
        if (j != null) {
            AbstractC0377b0.e(j, interfaceC0387g0, jZ, new C0379c0(this, interfaceC0387g0, 0));
            this.b = j;
        }
        if (j2 != null) {
            AbstractC0377b0.e(j2, interfaceC0387g0, jZ, new C0379c0(this, interfaceC0387g0, 1));
            this.d = j2;
        }
    }

    public final void c(androidx.compose.ui.layout.J j, androidx.compose.ui.layout.J j2, boolean z, long j3) {
        long jL = AbstractC0382e.l(z ? 1 : 2, j3);
        if (j != null) {
            int iG = androidx.compose.ui.unit.a.g(jL);
            M m = AbstractC0377b0.a;
            int iX = z ? j.x(iG) : j.X(iG);
            this.f = new C0212j(C0212j.a(iX, z ? j.X(iX) : j.x(iX)));
            this.b = j;
            this.c = null;
        }
        if (j2 != null) {
            int iG2 = androidx.compose.ui.unit.a.g(jL);
            M m2 = AbstractC0377b0.a;
            int iX2 = z ? j2.x(iG2) : j2.X(iG2);
            this.g = new C0212j(C0212j.a(iX2, z ? j2.X(iX2) : j2.x(iX2)));
            this.d = j2;
            this.e = null;
        }
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C0381d0)) {
            return false;
        }
        ((C0381d0) obj).getClass();
        return true;
    }

    public final int hashCode() {
        return Integer.hashCode(0) + androidx.compose.animation.d0.b(0, AbstractC0147y.k(2) * 31, 31);
    }

    public final String toString() {
        return android.support.v4.media.session.a.B("FlowLayoutOverflowState(type=", "Clip", ", minLinesToShowCollapse=0, minCrossAxisSizeToShowCollapse=0)");
    }
}
