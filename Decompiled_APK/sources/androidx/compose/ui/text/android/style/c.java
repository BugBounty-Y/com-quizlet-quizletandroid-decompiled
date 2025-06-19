package androidx.compose.ui.text.android.style;

import android.graphics.Canvas;
import android.graphics.Paint;
import android.text.Layout;
import android.text.style.LeadingMarginSpan;
import androidx.compose.ui.text.android.w;
import androidx.compose.ui.text.android.y;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3241q5;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class c implements LeadingMarginSpan {
    @Override // android.text.style.LeadingMarginSpan
    public final void drawLeadingMargin(Canvas canvas, Paint paint, int i, int i2, int i3, int i4, int i5, CharSequence charSequence, int i6, int i7, boolean z, Layout layout) {
        int lineForOffset;
        if (layout == null || paint == null || (lineForOffset = layout.getLineForOffset(i6)) != layout.getLineCount() - 1) {
            return;
        }
        w wVar = y.a;
        if (layout.getEllipsisCount(lineForOffset) > 0) {
            float fC = AbstractC3241q5.c(layout, lineForOffset, paint) + AbstractC3241q5.b(layout, lineForOffset, paint);
            if (fC == DefinitionKt.NO_Float_VALUE) {
                return;
            }
            Intrinsics.d(canvas);
            canvas.translate(fC, DefinitionKt.NO_Float_VALUE);
        }
    }

    @Override // android.text.style.LeadingMarginSpan
    public final int getLeadingMargin(boolean z) {
        return 0;
    }
}
