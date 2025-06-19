package androidx.compose.ui.platform;

import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.ui.platform.c, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0934c extends androidx.appcompat.app.y {
    public static C0934c f;
    public androidx.compose.ui.text.H d;
    public androidx.compose.ui.semantics.o e;

    @Override // androidx.appcompat.app.y
    public final int[] e(int i) {
        int iC;
        if (l().length() <= 0 || i >= l().length()) {
            return null;
        }
        try {
            androidx.compose.ui.semantics.o oVar = this.e;
            if (oVar == null) {
                Intrinsics.m("node");
                throw null;
            }
            int iRound = Math.round(oVar.e().d());
            if (i <= 0) {
                i = 0;
            }
            androidx.compose.ui.text.H h = this.d;
            if (h == null) {
                Intrinsics.m("layoutResult");
                throw null;
            }
            int iF = h.f(i);
            androidx.compose.ui.text.H h2 = this.d;
            if (h2 == null) {
                Intrinsics.m("layoutResult");
                throw null;
            }
            float fD = h2.b.d(iF) + iRound;
            androidx.compose.ui.text.H h3 = this.d;
            if (h3 == null) {
                Intrinsics.m("layoutResult");
                throw null;
            }
            if (h3 == null) {
                Intrinsics.m("layoutResult");
                throw null;
            }
            if (fD < h3.b.d(r0.f - 1)) {
                androidx.compose.ui.text.H h4 = this.d;
                if (h4 == null) {
                    Intrinsics.m("layoutResult");
                    throw null;
                }
                iC = h4.b.c(fD);
            } else {
                androidx.compose.ui.text.H h5 = this.d;
                if (h5 == null) {
                    Intrinsics.m("layoutResult");
                    throw null;
                }
                iC = h5.b.f;
            }
            return i(i, v(iC - 1, androidx.compose.ui.text.style.h.a) + 1);
        } catch (IllegalStateException unused) {
            return null;
        }
    }

    @Override // androidx.appcompat.app.y
    public final int[] o(int i) {
        int iC;
        if (l().length() <= 0 || i <= 0) {
            return null;
        }
        try {
            androidx.compose.ui.semantics.o oVar = this.e;
            if (oVar == null) {
                Intrinsics.m("node");
                throw null;
            }
            int iRound = Math.round(oVar.e().d());
            int length = l().length();
            if (length <= i) {
                i = length;
            }
            androidx.compose.ui.text.H h = this.d;
            if (h == null) {
                Intrinsics.m("layoutResult");
                throw null;
            }
            int iF = h.f(i);
            androidx.compose.ui.text.H h2 = this.d;
            if (h2 == null) {
                Intrinsics.m("layoutResult");
                throw null;
            }
            float fD = h2.b.d(iF) - iRound;
            if (fD > DefinitionKt.NO_Float_VALUE) {
                androidx.compose.ui.text.H h3 = this.d;
                if (h3 == null) {
                    Intrinsics.m("layoutResult");
                    throw null;
                }
                iC = h3.b.c(fD);
            } else {
                iC = 0;
            }
            if (i == l().length() && iC < iF) {
                iC++;
            }
            return i(v(iC, androidx.compose.ui.text.style.h.b), i);
        } catch (IllegalStateException unused) {
            return null;
        }
    }

    public final int v(int i, androidx.compose.ui.text.style.h hVar) {
        androidx.compose.ui.text.H h = this.d;
        if (h == null) {
            Intrinsics.m("layoutResult");
            throw null;
        }
        int i2 = h.i(i);
        androidx.compose.ui.text.H h2 = this.d;
        if (h2 == null) {
            Intrinsics.m("layoutResult");
            throw null;
        }
        if (hVar != h2.j(i2)) {
            androidx.compose.ui.text.H h3 = this.d;
            if (h3 != null) {
                return h3.i(i);
            }
            Intrinsics.m("layoutResult");
            throw null;
        }
        if (this.d != null) {
            return r6.e(i, false) - 1;
        }
        Intrinsics.m("layoutResult");
        throw null;
    }
}
