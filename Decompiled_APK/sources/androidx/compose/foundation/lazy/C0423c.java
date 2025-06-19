package androidx.compose.foundation.lazy;

import androidx.compose.foundation.gestures.E0;
import androidx.compose.foundation.gestures.EnumC0320d0;
import androidx.compose.foundation.lazy.layout.e0;
import androidx.compose.foundation.lazy.layout.h0;
import androidx.compose.foundation.pager.C0466e;
import androidx.compose.foundation.pager.I;
import kotlin.Unit;

/* renamed from: androidx.compose.foundation.lazy.c, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0423c implements e0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ boolean b;
    public final /* synthetic */ E0 c;

    public /* synthetic */ C0423c(E0 e0, boolean z, int i) {
        this.a = i;
        this.c = e0;
        this.b = z;
    }

    @Override // androidx.compose.foundation.lazy.layout.e0
    public final int a() {
        switch (this.a) {
            case 0:
                A a = (A) this.c;
                return (int) (a.h().n == EnumC0320d0.a ? a.h().a() & 4294967295L : a.h().a() >> 32);
            default:
                C0466e c0466e = (C0466e) this.c;
                return (int) (c0466e.k().e == EnumC0320d0.a ? c0466e.k().a() & 4294967295L : c0466e.k().a() >> 32);
        }
    }

    @Override // androidx.compose.foundation.lazy.layout.e0
    public final float b() {
        switch (this.a) {
            case 0:
                int iA = ((A) this.c).d.a();
                return (iA * com.pubmatic.sdk.video.a.GENERAL_NONLINEAR_AD_ERROR) + r0.d.b();
            default:
                C0466e c0466e = (C0466e) this.c;
                return kotlin.math.c.c(c0466e.c.j() * c0466e.n()) + (c0466e.j() * c0466e.n());
        }
    }

    @Override // androidx.compose.foundation.lazy.layout.e0
    public final int c() {
        switch (this.a) {
            case 0:
                A a = (A) this.c;
                return (-a.h().k) + a.h().o;
            default:
                C0466e c0466e = (C0466e) this.c;
                return (-c0466e.k().f) + c0466e.k().d;
        }
    }

    @Override // androidx.compose.foundation.lazy.layout.e0
    public final float d() {
        switch (this.a) {
            case 0:
                A a = (A) this.c;
                int iA = a.d.a();
                int iB = a.d.b();
                return a.d() ? (iA * com.pubmatic.sdk.video.a.GENERAL_NONLINEAR_AD_ERROR) + iB + 100 : (iA * com.pubmatic.sdk.video.a.GENERAL_NONLINEAR_AD_ERROR) + iB;
            default:
                C0466e c0466e = (C0466e) this.c;
                return I.a(c0466e.k(), c0466e.l());
        }
    }

    @Override // androidx.compose.foundation.lazy.layout.e0
    public final Object e(int i, h0 h0Var) {
        switch (this.a) {
            case 0:
                Object objJ = A.j((A) this.c, i, h0Var);
                if (objJ != kotlin.coroutines.intrinsics.a.a) {
                    break;
                }
                break;
            default:
                Object objS = androidx.compose.foundation.pager.E.s((C0466e) this.c, i, h0Var);
                if (objS != kotlin.coroutines.intrinsics.a.a) {
                    break;
                }
                break;
        }
        return Unit.a;
    }

    @Override // androidx.compose.foundation.lazy.layout.e0
    public final androidx.compose.ui.semantics.b f() {
        switch (this.a) {
            case 0:
                return this.b ? new androidx.compose.ui.semantics.b(-1, 1) : new androidx.compose.ui.semantics.b(1, -1);
            default:
                boolean z = this.b;
                C0466e c0466e = (C0466e) this.c;
                return z ? new androidx.compose.ui.semantics.b(c0466e.l(), 1) : new androidx.compose.ui.semantics.b(1, c0466e.l());
        }
    }
}
