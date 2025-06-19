package androidx.compose.ui.text.android.style;

import android.text.TextPaint;
import android.text.style.MetricAffectingSpan;

/* loaded from: classes.dex */
public final class a extends MetricAffectingSpan {
    public final /* synthetic */ int a;
    public final float b;

    public /* synthetic */ a(float f, int i) {
        this.a = i;
        this.b = f;
    }

    @Override // android.text.style.CharacterStyle
    public final void updateDrawState(TextPaint textPaint) {
        switch (this.a) {
            case 0:
                textPaint.baselineShift += (int) Math.ceil(textPaint.ascent() * this.b);
                break;
            default:
                textPaint.setTextSkewX(textPaint.getTextSkewX() + this.b);
                break;
        }
    }

    @Override // android.text.style.MetricAffectingSpan
    public final void updateMeasureState(TextPaint textPaint) {
        switch (this.a) {
            case 0:
                textPaint.baselineShift += (int) Math.ceil(textPaint.ascent() * this.b);
                break;
            default:
                textPaint.setTextSkewX(textPaint.getTextSkewX() + this.b);
                break;
        }
    }
}
