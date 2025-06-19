package androidx.compose.foundation.text;

import androidx.compose.animation.core.U0;
import androidx.compose.ui.text.C0995g;

/* loaded from: classes.dex */
public abstract class R0 {
    public static final U0 a = new U0(androidx.compose.ui.text.input.r.a, 0, 0, 2);

    public static final androidx.compose.ui.text.input.I a(androidx.compose.ui.text.input.K k, C0995g c0995g) {
        androidx.compose.ui.text.input.s sVar;
        androidx.compose.ui.text.input.I iE = k.e(c0995g);
        int length = c0995g.a.length();
        C0995g c0995g2 = iE.a;
        int length2 = c0995g2.a.length();
        int iMin = Math.min(length, 100);
        int i = 0;
        while (true) {
            sVar = iE.b;
            if (i >= iMin) {
                break;
            }
            b(sVar.p(i), length2, i);
            i++;
        }
        b(sVar.p(length), length2, length);
        int iMin2 = Math.min(length2, 100);
        for (int i2 = 0; i2 < iMin2; i2++) {
            c(sVar.g(i2), length, i2);
        }
        c(sVar.g(length2), length, length2);
        return new androidx.compose.ui.text.input.I(c0995g2, new U0(sVar, c0995g.a.length(), c0995g2.a.length(), 2));
    }

    public static final void b(int i, int i2, int i3) {
        if (i < 0 || i > i2) {
            throw new IllegalStateException(android.support.v4.media.session.a.q(android.support.v4.media.session.a.w("OffsetMapping.originalToTransformed returned invalid mapping: ", i3, " -> ", " is not in range of transformed text [0, ", i), i2, ']').toString());
        }
    }

    public static final void c(int i, int i2, int i3) {
        if (i < 0 || i > i2) {
            throw new IllegalStateException(android.support.v4.media.session.a.q(android.support.v4.media.session.a.w("OffsetMapping.transformedToOriginal returned invalid mapping: ", i3, " -> ", " is not in range of original text [0, ", i), i2, ']').toString());
        }
    }
}
