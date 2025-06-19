package androidx.compose.ui.text.platform.style;

import android.graphics.Paint;
import android.text.TextPaint;
import android.text.style.CharacterStyle;
import android.text.style.UpdateAppearance;
import androidx.compose.ui.graphics.drawscope.e;
import androidx.compose.ui.graphics.drawscope.g;
import androidx.compose.ui.graphics.drawscope.h;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class a extends CharacterStyle implements UpdateAppearance {
    public final e a;

    public a(e eVar) {
        this.a = eVar;
    }

    @Override // android.text.style.CharacterStyle
    public final void updateDrawState(TextPaint textPaint) {
        if (textPaint != null) {
            g gVar = g.a;
            e eVar = this.a;
            if (Intrinsics.b(eVar, gVar)) {
                textPaint.setStyle(Paint.Style.FILL);
                return;
            }
            if (eVar instanceof h) {
                textPaint.setStyle(Paint.Style.STROKE);
                textPaint.setStrokeWidth(((h) eVar).a);
                textPaint.setStrokeMiter(((h) eVar).b);
                int i = ((h) eVar).d;
                textPaint.setStrokeJoin(i == 0 ? Paint.Join.MITER : i == 1 ? Paint.Join.ROUND : i == 2 ? Paint.Join.BEVEL : Paint.Join.MITER);
                int i2 = ((h) eVar).c;
                textPaint.setStrokeCap(i2 == 0 ? Paint.Cap.BUTT : i2 == 1 ? Paint.Cap.ROUND : i2 == 2 ? Paint.Cap.SQUARE : Paint.Cap.BUTT);
                ((h) eVar).getClass();
                textPaint.setPathEffect(null);
            }
        }
    }
}
