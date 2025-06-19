package androidx.compose.ui.text.android.style;

import android.graphics.Rect;
import android.text.TextPaint;
import android.text.style.MetricAffectingSpan;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class e extends MetricAffectingSpan {
    public final /* synthetic */ int a;
    public final float b;

    public e() {
        this.a = 1;
        this.b = 0.57f;
    }

    public void a(TextPaint textPaint) {
        Rect rect = new Rect();
        textPaint.getTextBounds("1A", 0, 2, rect);
        int i = rect.top - rect.bottom;
        textPaint.setTextSize(textPaint.getTextSize() * this.b);
        textPaint.getTextBounds("1A", 0, 2, rect);
        textPaint.baselineShift += (rect.bottom - rect.top) + i;
    }

    @Override // android.text.style.CharacterStyle
    public final void updateDrawState(TextPaint ds) {
        switch (this.a) {
            case 0:
                ds.setLetterSpacing(this.b);
                break;
            default:
                Intrinsics.checkNotNullParameter(ds, "ds");
                a(ds);
                break;
        }
    }

    @Override // android.text.style.MetricAffectingSpan
    public final void updateMeasureState(TextPaint ds) {
        switch (this.a) {
            case 0:
                ds.setLetterSpacing(this.b);
                break;
            default:
                Intrinsics.checkNotNullParameter(ds, "ds");
                a(ds);
                break;
        }
    }

    public e(float f) {
        this.a = 0;
        this.b = f;
    }
}
