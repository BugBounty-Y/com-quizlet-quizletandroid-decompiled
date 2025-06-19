package androidx.compose.foundation.text.input.internal;

import android.view.inputmethod.ExtractedText;
import androidx.compose.foundation.text.C0492h0;
import androidx.compose.foundation.text.K0;
import androidx.compose.foundation.text.selection.i0;
import androidx.compose.ui.platform.Y0;
import androidx.compose.ui.text.H;
import androidx.compose.ui.text.K;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3205m5;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.text.StringsKt;

/* loaded from: classes.dex */
public abstract class x {
    public static final long a(C0492h0 c0492h0, androidx.compose.ui.geometry.c cVar, androidx.compose.ui.geometry.c cVar2, int i) {
        long jF = f(c0492h0, cVar, i);
        if (K.b(jF)) {
            return K.b;
        }
        long jF2 = f(c0492h0, cVar2, i);
        if (K.b(jF2)) {
            return K.b;
        }
        int i2 = (int) (jF >> 32);
        int i3 = (int) (jF2 & 4294967295L);
        return AbstractC3205m5.c(Math.min(i2, i2), Math.max(i3, i3));
    }

    public static final boolean b(H h, int i) {
        int iF = h.f(i);
        return i == h.i(iF) || i == h.e(iF, false) ? h.j(i) != h.a(i) : h.a(i) != h.a(i - 1);
    }

    public static final ExtractedText c(androidx.compose.ui.text.input.A a) {
        ExtractedText extractedText = new ExtractedText();
        String str = a.a.a;
        extractedText.text = str;
        extractedText.startOffset = 0;
        extractedText.partialEndOffset = str.length();
        extractedText.partialStartOffset = -1;
        long j = a.b;
        extractedText.selectionStart = K.e(j);
        extractedText.selectionEnd = K.d(j);
        extractedText.flags = !StringsKt.F(a.a.a, '\n', false) ? 1 : 0;
        return extractedText;
    }

    public static final boolean d(androidx.compose.ui.geometry.c cVar, float f, float f2) {
        return f <= cVar.c && cVar.a <= f && f2 <= cVar.d && cVar.b <= f2;
    }

    public static final int e(androidx.compose.ui.text.o oVar, long j, Y0 y0) {
        float fG = y0 != null ? y0.g() : DefinitionKt.NO_Float_VALUE;
        int iC = oVar.c(androidx.compose.ui.geometry.b.e(j));
        if (androidx.compose.ui.geometry.b.e(j) < oVar.d(iC) - fG || androidx.compose.ui.geometry.b.e(j) > oVar.b(iC) + fG || androidx.compose.ui.geometry.b.d(j) < (-fG) || androidx.compose.ui.geometry.b.d(j) > oVar.d + fG) {
            return -1;
        }
        return iC;
    }

    public static final long f(C0492h0 c0492h0, androidx.compose.ui.geometry.c cVar, int i) {
        K0 k0D = c0492h0.d();
        androidx.compose.ui.text.o oVar = k0D != null ? k0D.a.b : null;
        androidx.compose.ui.layout.r rVarC = c0492h0.c();
        return (oVar == null || rVarC == null) ? K.b : oVar.f(cVar.j(rVarC.N(0L)), i, androidx.compose.ui.text.F.b);
    }

    public static final boolean g(int i) {
        int type = Character.getType(i);
        return type == 23 || type == 20 || type == 22 || type == 30 || type == 29 || type == 24 || type == 21;
    }

    public static final boolean h(int i) {
        return Character.isWhitespace(i) || i == 160;
    }

    public static final boolean i(int i) {
        int type;
        return (!h(i) || (type = Character.getType(i)) == 14 || type == 13 || i == 10) ? false : true;
    }

    public static final androidx.compose.ui.q j(androidx.compose.ui.q qVar, g gVar, C0492h0 c0492h0, i0 i0Var) {
        return qVar.g(new LegacyAdaptingPlatformTextInputModifier(gVar, c0492h0, i0Var));
    }
}
