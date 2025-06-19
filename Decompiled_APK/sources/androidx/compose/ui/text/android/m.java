package androidx.compose.ui.text.android;

import android.os.Build;
import android.text.BoringLayout;
import android.text.TextDirectionHeuristic;
import android.text.TextPaint;

/* loaded from: classes.dex */
public final class m {
    public final CharSequence a;
    public final TextPaint b;
    public final int c;
    public float d = Float.NaN;
    public float e = Float.NaN;
    public BoringLayout.Metrics f;
    public boolean g;

    public m(CharSequence charSequence, TextPaint textPaint, int i) {
        this.a = charSequence;
        this.b = textPaint;
        this.c = i;
    }

    public final BoringLayout.Metrics a() {
        if (!this.g) {
            TextDirectionHeuristic textDirectionHeuristicA = y.a(this.c);
            int i = Build.VERSION.SDK_INT;
            CharSequence charSequence = this.a;
            TextPaint textPaint = this.b;
            this.f = i >= 33 ? c.b(charSequence, textPaint, textDirectionHeuristicA) : d.b(charSequence, textPaint, textDirectionHeuristicA);
            this.g = true;
        }
        return this.f;
    }

    /* JADX WARN: Removed duplicated region for block: B:24:0x005c  */
    /* JADX WARN: Removed duplicated region for block: B:27:0x0065  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final float b() {
        /*
            r8 = this;
            float r0 = r8.d
            boolean r0 = java.lang.Float.isNaN(r0)
            if (r0 != 0) goto Lb
            float r0 = r8.d
            return r0
        Lb:
            android.text.BoringLayout$Metrics r0 = r8.a()
            r1 = -1
            if (r0 == 0) goto L15
            int r0 = r0.width
            goto L16
        L15:
            r0 = r1
        L16:
            float r0 = (float) r0
            r2 = 0
            int r3 = (r0 > r2 ? 1 : (r0 == r2 ? 0 : -1))
            android.text.TextPaint r4 = r8.b
            java.lang.CharSequence r5 = r8.a
            if (r3 >= 0) goto L2f
            int r0 = r5.length()
            r3 = 0
            float r0 = android.text.Layout.getDesiredWidth(r5, r3, r0, r4)
            double r6 = (double) r0
            double r6 = java.lang.Math.ceil(r6)
            float r0 = (float) r6
        L2f:
            int r3 = (r0 > r2 ? 1 : (r0 == r2 ? 0 : -1))
            if (r3 != 0) goto L34
            goto L68
        L34:
            boolean r3 = r5 instanceof android.text.Spanned
            if (r3 == 0) goto L5c
            android.text.Spanned r5 = (android.text.Spanned) r5
            int r3 = r5.length()
            java.lang.Class<androidx.compose.ui.text.android.style.f> r6 = androidx.compose.ui.text.android.style.f.class
            int r3 = r5.nextSpanTransition(r1, r3, r6)
            int r6 = r5.length()
            if (r3 == r6) goto L4b
            goto L65
        L4b:
            int r3 = r5.length()
            java.lang.Class<androidx.compose.ui.text.android.style.e> r6 = androidx.compose.ui.text.android.style.e.class
            int r1 = r5.nextSpanTransition(r1, r3, r6)
            int r3 = r5.length()
            if (r1 == r3) goto L5c
            goto L65
        L5c:
            float r1 = r4.getLetterSpacing()
            int r1 = (r1 > r2 ? 1 : (r1 == r2 ? 0 : -1))
            if (r1 != 0) goto L65
            goto L68
        L65:
            r1 = 1056964608(0x3f000000, float:0.5)
            float r0 = r0 + r1
        L68:
            r8.d = r0
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.text.android.m.b():float");
    }
}
