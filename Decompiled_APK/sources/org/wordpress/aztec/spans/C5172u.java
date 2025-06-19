package org.wordpress.aztec.spans;

import android.graphics.Paint;
import android.text.Spanned;
import android.text.style.LineHeightSpan;
import android.text.style.UpdateLayout;
import com.google.android.gms.internal.mlkit_vision_camera.C2;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: org.wordpress.aztec.spans.u, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C5172u implements LineHeightSpan, UpdateLayout {
    public int a;

    public C5172u(int i) {
        this.a = i;
    }

    @Override // android.text.style.LineHeightSpan
    public final void chooseHeight(CharSequence charSequence, int i, int i2, int i3, int i4, Paint.FontMetricsInt fm) {
        Intrinsics.checkNotNullParameter(fm, "fm");
        Intrinsics.e(charSequence, "null cannot be cast to non-null type android.text.Spanned");
        Spanned spanned = (Spanned) charSequence;
        int spanEnd = spanned.getSpanEnd(this);
        Object[] spans = spanned.getSpans(spanEnd, spanEnd, C5168p.class);
        Intrinsics.checkNotNullExpressionValue(spans, "getSpans(...)");
        int length = spans.length;
        int i5 = 0;
        int i6 = 0;
        while (true) {
            if (i6 < length) {
                if (spanned.getSpanEnd((C5168p) spans[i6]) == spanEnd) {
                    break;
                } else {
                    i6++;
                }
            } else if (spanned.length() < spanEnd || spanned.charAt(spanEnd - 1) != C2.c) {
                i5 = this.a * 2;
            }
        }
        if (i2 == spanEnd) {
            fm.descent += i5;
            fm.bottom += i5;
        }
    }
}
