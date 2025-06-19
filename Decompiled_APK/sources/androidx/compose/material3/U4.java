package androidx.compose.material3;

import androidx.compose.animation.core.C0238e;
import androidx.compose.ui.node.InterfaceC0926w;
import com.google.android.gms.internal.mlkit_vision_barcode.L5;
import com.google.android.gms.internal.mlkit_vision_barcode.O5;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class U4 extends androidx.compose.ui.p implements InterfaceC0926w {
    public androidx.compose.foundation.interaction.l n;
    public boolean o;
    public boolean p;
    public C0238e q;
    public C0238e r;
    public float s;
    public float t;

    @Override // androidx.compose.ui.p
    public final boolean B0() {
        return false;
    }

    @Override // androidx.compose.ui.p
    public final void E0() {
        kotlinx.coroutines.E.A(A0(), null, null, new T4(this, null), 3);
    }

    @Override // androidx.compose.ui.node.InterfaceC0926w
    public final androidx.compose.ui.layout.L h(androidx.compose.ui.layout.M m, androidx.compose.ui.layout.J j, long j2) {
        boolean z = false;
        float fC0 = m.c0(this.p ? androidx.compose.material3.tokens.A.a : ((j.b(androidx.compose.ui.unit.a.h(j2)) != 0 && j.z(androidx.compose.ui.unit.a.g(j2)) != 0) || this.o) ? AbstractC0679l4.a : AbstractC0679l4.b);
        C0238e c0238e = this.r;
        int iFloatValue = (int) (c0238e != null ? ((Number) c0238e.d()).floatValue() : fC0);
        if (iFloatValue >= 0 && iFloatValue >= 0) {
            z = true;
        }
        if (!z) {
            O5.e("width(" + iFloatValue + ") and height(" + iFloatValue + ") must be >= 0");
            throw null;
        }
        androidx.compose.ui.layout.W wB = j.B(L5.m(iFloatValue, iFloatValue, iFloatValue, iFloatValue));
        float fC02 = m.c0((AbstractC0679l4.d - m.R(fC0)) / 2.0f);
        float fC03 = m.c0((AbstractC0679l4.c - AbstractC0679l4.a) - AbstractC0679l4.e);
        boolean z2 = this.p;
        if (z2 && this.o) {
            fC02 = fC03 - m.c0(androidx.compose.material3.tokens.A.e);
        } else if (z2 && !this.o) {
            fC02 = m.c0(androidx.compose.material3.tokens.A.e);
        } else if (this.o) {
            fC02 = fC03;
        }
        C0238e c0238e2 = this.r;
        if (!Intrinsics.a(c0238e2 != null ? (Float) ((androidx.compose.runtime.L0) c0238e2.e).getValue() : null, fC0)) {
            kotlinx.coroutines.E.A(A0(), null, null, new R4(this, fC0, null), 3);
        }
        C0238e c0238e3 = this.q;
        if (!Intrinsics.a(c0238e3 != null ? (Float) ((androidx.compose.runtime.L0) c0238e3.e).getValue() : null, fC02)) {
            kotlinx.coroutines.E.A(A0(), null, null, new S4(this, fC02, null), 3);
        }
        if (Float.isNaN(this.t) && Float.isNaN(this.s)) {
            this.t = fC0;
            this.s = fC02;
        }
        return m.n0(iFloatValue, iFloatValue, kotlin.collections.V.c(), new androidx.compose.foundation.gestures.n1(wB, this, fC02));
    }
}
