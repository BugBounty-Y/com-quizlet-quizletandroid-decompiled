package androidx.compose.ui.text;

import android.graphics.RectF;
import android.text.Layout;
import androidx.compose.animation.d0;
import androidx.compose.foundation.O0;
import androidx.compose.ui.graphics.C0850j;
import com.google.android.gms.ads.internal.client.C1608n;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3169i5;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3205m5;
import com.google.android.gms.internal.mlkit_vision_barcode.Q4;
import com.skydoves.balloon.internals.DefinitionKt;
import java.text.BreakIterator;
import java.util.ArrayList;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class H {
    public final G a;
    public final o b;
    public final long c;
    public final float d;
    public final float e;
    public final ArrayList f;

    public H(G g, o oVar, long j) {
        this.a = g;
        this.b = oVar;
        this.c = j;
        ArrayList arrayList = oVar.h;
        boolean zIsEmpty = arrayList.isEmpty();
        float fD = DefinitionKt.NO_Float_VALUE;
        this.d = zIsEmpty ? 0.0f : ((q) arrayList.get(0)).a.d.d(0);
        if (!arrayList.isEmpty()) {
            q qVar = (q) CollectionsKt.U(arrayList);
            fD = qVar.a.d.d(r4.f - 1) + qVar.f;
        }
        this.e = fD;
        this.f = oVar.g;
    }

    public final androidx.compose.ui.text.style.h a(int i) {
        o oVar = this.b;
        oVar.j(i);
        int length = ((C0995g) oVar.a.b).a.length();
        ArrayList arrayList = oVar.h;
        q qVar = (q) arrayList.get(i == length ? kotlin.collections.B.i(arrayList) : AbstractC3169i5.b(i, arrayList));
        return qVar.a.d.e.isRtlCharAt(qVar.b(i)) ? androidx.compose.ui.text.style.h.b : androidx.compose.ui.text.style.h.a;
    }

    public final androidx.compose.ui.geometry.c b(int i) {
        float fI;
        float fI2;
        float fH;
        float fH2;
        o oVar = this.b;
        oVar.i(i);
        ArrayList arrayList = oVar.h;
        q qVar = (q) arrayList.get(AbstractC3169i5.b(i, arrayList));
        C0982b c0982b = qVar.a;
        int iB = qVar.b(i);
        CharSequence charSequence = c0982b.e;
        if (iB < 0 || iB >= charSequence.length()) {
            StringBuilder sbV = android.support.v4.media.session.a.v(iB, "offset(", ") is out of bounds [0,");
            sbV.append(charSequence.length());
            sbV.append(')');
            throw new IllegalArgumentException(sbV.toString().toString());
        }
        androidx.compose.ui.text.android.x xVar = c0982b.d;
        Layout layout = xVar.e;
        int lineForOffset = layout.getLineForOffset(iB);
        float fG = xVar.g(lineForOffset);
        float fE = xVar.e(lineForOffset);
        boolean z = layout.getParagraphDirection(lineForOffset) == 1;
        boolean zIsRtlCharAt = layout.isRtlCharAt(iB);
        if (!z || zIsRtlCharAt) {
            if (z && zIsRtlCharAt) {
                fH = xVar.i(iB, false);
                fH2 = xVar.i(iB + 1, true);
            } else if (zIsRtlCharAt) {
                fH = xVar.h(iB, false);
                fH2 = xVar.h(iB + 1, true);
            } else {
                fI = xVar.i(iB, false);
                fI2 = xVar.i(iB + 1, true);
            }
            float f = fH;
            fI = fH2;
            fI2 = f;
        } else {
            fI = xVar.h(iB, false);
            fI2 = xVar.h(iB + 1, true);
        }
        RectF rectF = new RectF(fI, fG, fI2, fE);
        float f2 = rectF.left;
        float f3 = rectF.top;
        float f4 = rectF.right;
        float f5 = rectF.bottom;
        long jC = Q4.c(DefinitionKt.NO_Float_VALUE, qVar.f);
        return new androidx.compose.ui.geometry.c(androidx.compose.ui.geometry.b.d(jC) + f2, androidx.compose.ui.geometry.b.e(jC) + f3, androidx.compose.ui.geometry.b.d(jC) + f4, androidx.compose.ui.geometry.b.e(jC) + f5);
    }

    public final androidx.compose.ui.geometry.c c(int i) {
        o oVar = this.b;
        oVar.j(i);
        int length = ((C0995g) oVar.a.b).a.length();
        ArrayList arrayList = oVar.h;
        q qVar = (q) arrayList.get(i == length ? kotlin.collections.B.i(arrayList) : AbstractC3169i5.b(i, arrayList));
        C0982b c0982b = qVar.a;
        int iB = qVar.b(i);
        CharSequence charSequence = c0982b.e;
        if (iB < 0 || iB > charSequence.length()) {
            StringBuilder sbV = android.support.v4.media.session.a.v(iB, "offset(", ") is out of bounds [0,");
            sbV.append(charSequence.length());
            sbV.append(']');
            throw new IllegalArgumentException(sbV.toString().toString());
        }
        androidx.compose.ui.text.android.x xVar = c0982b.d;
        float fH = xVar.h(iB, false);
        int lineForOffset = xVar.e.getLineForOffset(iB);
        float fG = xVar.g(lineForOffset);
        float fE = xVar.e(lineForOffset);
        long jC = Q4.c(DefinitionKt.NO_Float_VALUE, qVar.f);
        return new androidx.compose.ui.geometry.c(androidx.compose.ui.geometry.b.d(jC) + fH, androidx.compose.ui.geometry.b.e(jC) + fG, androidx.compose.ui.geometry.b.d(jC) + fH, androidx.compose.ui.geometry.b.e(jC) + fE);
    }

    public final boolean d() {
        long j = this.c;
        float f = (int) (j >> 32);
        o oVar = this.b;
        return f < oVar.d || oVar.c || ((float) ((int) (j & 4294967295L))) < oVar.e;
    }

    public final int e(int i, boolean z) {
        int iF;
        o oVar = this.b;
        oVar.k(i);
        ArrayList arrayList = oVar.h;
        q qVar = (q) arrayList.get(AbstractC3169i5.c(i, arrayList));
        C0982b c0982b = qVar.a;
        int i2 = i - qVar.d;
        androidx.compose.ui.text.android.x xVar = c0982b.d;
        if (z) {
            Layout layout = xVar.e;
            if (layout.getEllipsisStart(i2) == 0) {
                C1608n c1608nC = xVar.c();
                Layout layout2 = (Layout) c1608nC.a;
                iF = c1608nC.s(layout2.getLineEnd(i2), layout2.getLineStart(i2));
            } else {
                iF = layout.getEllipsisStart(i2) + layout.getLineStart(i2);
            }
        } else {
            iF = xVar.f(i2);
        }
        return iF + qVar.b;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof H)) {
            return false;
        }
        H h = (H) obj;
        return Intrinsics.b(this.a, h.a) && this.b.equals(h.b) && androidx.compose.ui.unit.j.a(this.c, h.c) && this.d == h.d && this.e == h.e && Intrinsics.b(this.f, h.f);
    }

    public final int f(int i) {
        o oVar = this.b;
        int length = ((C0995g) oVar.a.b).a.length();
        ArrayList arrayList = oVar.h;
        q qVar = (q) arrayList.get(i >= length ? kotlin.collections.B.i(arrayList) : i < 0 ? 0 : AbstractC3169i5.b(i, arrayList));
        return qVar.a.d.e.getLineForOffset(qVar.b(i)) + qVar.d;
    }

    public final float g(int i) {
        o oVar = this.b;
        oVar.k(i);
        ArrayList arrayList = oVar.h;
        q qVar = (q) arrayList.get(AbstractC3169i5.c(i, arrayList));
        C0982b c0982b = qVar.a;
        int i2 = i - qVar.d;
        androidx.compose.ui.text.android.x xVar = c0982b.d;
        return xVar.e.getLineLeft(i2) + (i2 == xVar.f + (-1) ? xVar.i : DefinitionKt.NO_Float_VALUE);
    }

    public final float h(int i) {
        o oVar = this.b;
        oVar.k(i);
        ArrayList arrayList = oVar.h;
        q qVar = (q) arrayList.get(AbstractC3169i5.c(i, arrayList));
        C0982b c0982b = qVar.a;
        int i2 = i - qVar.d;
        androidx.compose.ui.text.android.x xVar = c0982b.d;
        return xVar.e.getLineRight(i2) + (i2 == xVar.f + (-1) ? xVar.j : DefinitionKt.NO_Float_VALUE);
    }

    public final int hashCode() {
        return this.f.hashCode() + android.support.v4.media.session.a.b(android.support.v4.media.session.a.b(d0.d((this.b.hashCode() + (this.a.hashCode() * 31)) * 31, 31, this.c), this.d, 31), this.e, 31);
    }

    public final int i(int i) {
        o oVar = this.b;
        oVar.k(i);
        ArrayList arrayList = oVar.h;
        q qVar = (q) arrayList.get(AbstractC3169i5.c(i, arrayList));
        C0982b c0982b = qVar.a;
        return c0982b.d.e.getLineStart(i - qVar.d) + qVar.b;
    }

    public final androidx.compose.ui.text.style.h j(int i) {
        o oVar = this.b;
        oVar.j(i);
        int length = ((C0995g) oVar.a.b).a.length();
        ArrayList arrayList = oVar.h;
        q qVar = (q) arrayList.get(i == length ? kotlin.collections.B.i(arrayList) : AbstractC3169i5.b(i, arrayList));
        C0982b c0982b = qVar.a;
        int iB = qVar.b(i);
        androidx.compose.ui.text.android.x xVar = c0982b.d;
        return xVar.e.getParagraphDirection(xVar.e.getLineForOffset(iB)) == 1 ? androidx.compose.ui.text.style.h.a : androidx.compose.ui.text.style.h.b;
    }

    public final C0850j k(int i, int i2) {
        o oVar = this.b;
        C0995g c0995g = (C0995g) oVar.a.b;
        if (i < 0 || i > i2 || i2 > c0995g.a.length()) {
            StringBuilder sbW = android.support.v4.media.session.a.w("Start(", i, ") or End(", ") is out of range [0..", i2);
            sbW.append(c0995g.a.length());
            sbW.append("), or start > end!");
            throw new IllegalArgumentException(sbW.toString().toString());
        }
        if (i == i2) {
            return androidx.compose.ui.graphics.F.h();
        }
        C0850j c0850jH = androidx.compose.ui.graphics.F.h();
        AbstractC3169i5.e(oVar.h, AbstractC3205m5.c(i, i2), new O0(c0850jH, i, i2, 4));
        return c0850jH;
    }

    public final long l(int i) {
        int iPreceding;
        int iFollowing;
        int iFollowing2;
        o oVar = this.b;
        oVar.j(i);
        int length = ((C0995g) oVar.a.b).a.length();
        ArrayList arrayList = oVar.h;
        q qVar = (q) arrayList.get(i == length ? kotlin.collections.B.i(arrayList) : AbstractC3169i5.b(i, arrayList));
        C0982b c0982b = qVar.a;
        int iB = qVar.b(i);
        androidx.compose.ui.text.android.selection.f fVarJ = c0982b.d.j();
        fVarJ.b(iB);
        BreakIterator breakIterator = (BreakIterator) fVarJ.e;
        if (fVarJ.i(breakIterator.preceding(iB))) {
            fVarJ.b(iB);
            iPreceding = iB;
            while (iPreceding != -1 && (!fVarJ.i(iPreceding) || fVarJ.g(iPreceding))) {
                fVarJ.b(iPreceding);
                iPreceding = breakIterator.preceding(iPreceding);
            }
        } else {
            fVarJ.b(iB);
            iPreceding = fVarJ.h(iB) ? (!breakIterator.isBoundary(iB) || fVarJ.f(iB)) ? breakIterator.preceding(iB) : iB : fVarJ.f(iB) ? breakIterator.preceding(iB) : -1;
        }
        if (iPreceding == -1) {
            iPreceding = iB;
        }
        fVarJ.b(iB);
        if (fVarJ.g(breakIterator.following(iB))) {
            fVarJ.b(iB);
            iFollowing = iB;
            while (iFollowing != -1 && (fVarJ.i(iFollowing) || !fVarJ.g(iFollowing))) {
                fVarJ.b(iFollowing);
                iFollowing = breakIterator.following(iFollowing);
            }
        } else {
            fVarJ.b(iB);
            if (fVarJ.f(iB)) {
                if (!breakIterator.isBoundary(iB) || fVarJ.h(iB)) {
                    iFollowing2 = breakIterator.following(iB);
                    iFollowing = iFollowing2;
                } else {
                    iFollowing = iB;
                }
            } else if (fVarJ.h(iB)) {
                iFollowing2 = breakIterator.following(iB);
                iFollowing = iFollowing2;
            } else {
                iFollowing = -1;
            }
        }
        if (iFollowing != -1) {
            iB = iFollowing;
        }
        return qVar.a(AbstractC3205m5.c(iPreceding, iB), false);
    }

    public final String toString() {
        return "TextLayoutResult(layoutInput=" + this.a + ", multiParagraph=" + this.b + ", size=" + ((Object) androidx.compose.ui.unit.j.b(this.c)) + ", firstBaseline=" + this.d + ", lastBaseline=" + this.e + ", placeholderRects=" + this.f + ')';
    }
}
