package androidx.compose.ui.text.android.style;

import android.text.TextPaint;
import android.text.style.MetricAffectingSpan;
import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes.dex */
public final class f extends MetricAffectingSpan {
    public final float a;

    public f(float f) {
        this.a = f;
    }

    @Override // android.text.style.CharacterStyle
    public final void updateDrawState(TextPaint textPaint) {
        float textScaleX = textPaint.getTextScaleX() * textPaint.getTextSize();
        if (textScaleX == DefinitionKt.NO_Float_VALUE) {
            return;
        }
        textPaint.setLetterSpacing(this.a / textScaleX);
    }

    @Override // android.text.style.MetricAffectingSpan
    public final void updateMeasureState(TextPaint textPaint) {
        float textScaleX = textPaint.getTextScaleX() * textPaint.getTextSize();
        if (textScaleX == DefinitionKt.NO_Float_VALUE) {
            return;
        }
        textPaint.setLetterSpacing(this.a / textScaleX);
    }
}
