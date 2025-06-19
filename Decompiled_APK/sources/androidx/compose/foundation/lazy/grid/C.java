package androidx.compose.foundation.lazy.grid;

import androidx.compose.foundation.gestures.EnumC0320d0;
import androidx.compose.foundation.lazy.layout.e0;
import androidx.compose.foundation.lazy.layout.h0;
import androidx.compose.ui.layout.L;
import com.google.android.gms.internal.mlkit_vision_barcode.R5;
import kotlin.Unit;

/* loaded from: classes.dex */
public final class C implements e0 {
    public final /* synthetic */ A a;

    public C(A a) {
        this.a = a;
    }

    @Override // androidx.compose.foundation.lazy.layout.e0
    public final int a() {
        long jA;
        A a = this.a;
        if (a.g().k == EnumC0320d0.a) {
            L l = a.g().n;
            jA = R5.a(l.getWidth(), l.b()) & 4294967295L;
        } else {
            L l2 = a.g().n;
            jA = R5.a(l2.getWidth(), l2.b()) >> 32;
        }
        return (int) jA;
    }

    @Override // androidx.compose.foundation.lazy.layout.e0
    public final float b() {
        int iA = this.a.b.a();
        return (iA * com.pubmatic.sdk.video.a.GENERAL_NONLINEAR_AD_ERROR) + r0.b.b();
    }

    @Override // androidx.compose.foundation.lazy.layout.e0
    public final int c() {
        A a = this.a;
        return (-a.g().h) + a.g().l;
    }

    @Override // androidx.compose.foundation.lazy.layout.e0
    public final float d() {
        A a = this.a;
        int iA = a.b.a();
        int iB = a.b.b();
        return a.d() ? (iA * com.pubmatic.sdk.video.a.GENERAL_NONLINEAR_AD_ERROR) + iB + 100 : (iA * com.pubmatic.sdk.video.a.GENERAL_NONLINEAR_AD_ERROR) + iB;
    }

    @Override // androidx.compose.foundation.lazy.layout.e0
    public final Object e(int i, h0 h0Var) {
        Object objI = A.i(this.a, i, h0Var);
        return objI == kotlin.coroutines.intrinsics.a.a ? objI : Unit.a;
    }

    @Override // androidx.compose.foundation.lazy.layout.e0
    public final androidx.compose.ui.semantics.b f() {
        return new androidx.compose.ui.semantics.b(-1, -1);
    }
}
