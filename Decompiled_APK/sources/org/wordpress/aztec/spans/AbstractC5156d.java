package org.wordpress.aztec.spans;

import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.Rect;
import android.graphics.drawable.Drawable;
import android.text.Layout;
import android.text.style.DynamicDrawableSpan;
import java.lang.ref.WeakReference;
import kotlin.jvm.internal.Intrinsics;
import org.wordpress.aztec.AztecText;

/* renamed from: org.wordpress.aztec.spans.d, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public abstract class AbstractC5156d extends DynamicDrawableSpan {
    public final Drawable a;
    public WeakReference b;
    public final double c;

    /* JADX WARN: Removed duplicated region for block: B:19:0x0034  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public AbstractC5156d(android.graphics.drawable.Drawable r6) {
        /*
            r5 = this;
            r5.<init>()
            r5.a = r6
            r0 = 4607182418800017408(0x3ff0000000000000, double:1.0)
            r5.c = r0
            r2 = -1
            if (r6 == 0) goto L11
            int r3 = r6.getIntrinsicWidth()
            goto L12
        L11:
            r3 = r2
        L12:
            r4 = 1
            if (r3 <= r2) goto L34
            if (r6 == 0) goto L1c
            int r3 = r6.getIntrinsicHeight()
            goto L1d
        L1c:
            r3 = r2
        L1d:
            if (r3 <= r2) goto L34
            if (r6 == 0) goto L26
            int r2 = r6.getIntrinsicWidth()
            goto L27
        L26:
            r2 = r4
        L27:
            double r2 = (double) r2
            double r2 = r2 * r0
            if (r6 == 0) goto L2f
            int r4 = r6.getIntrinsicHeight()
        L2f:
            double r0 = (double) r4
            double r2 = r2 / r0
            r5.c = r2
            goto L67
        L34:
            if (r6 == 0) goto L41
            android.graphics.Rect r2 = r6.getBounds()
            if (r2 == 0) goto L41
            boolean r2 = r2.isEmpty()
            goto L42
        L41:
            r2 = r4
        L42:
            if (r2 != 0) goto L65
            if (r6 == 0) goto L51
            android.graphics.Rect r2 = r6.getBounds()
            if (r2 == 0) goto L51
            int r2 = r2.width()
            goto L52
        L51:
            r2 = 0
        L52:
            double r2 = (double) r2
            double r0 = r0 * r2
            if (r6 == 0) goto L60
            android.graphics.Rect r2 = r6.getBounds()
            if (r2 == 0) goto L60
            int r4 = r2.height()
        L60:
            double r2 = (double) r4
            double r0 = r0 / r2
            r5.c = r0
            goto L67
        L65:
            r5.c = r0
        L67:
            b(r6)
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: org.wordpress.aztec.spans.AbstractC5156d.<init>(android.graphics.drawable.Drawable):void");
    }

    public static final void b(Drawable drawable) {
        if (drawable == null || !drawable.getBounds().isEmpty()) {
            return;
        }
        if (drawable.getIntrinsicWidth() > -1 || drawable.getIntrinsicHeight() > -1) {
            drawable.setBounds(0, 0, drawable.getIntrinsicWidth(), drawable.getIntrinsicHeight());
        }
    }

    @Override // android.text.style.DynamicDrawableSpan, android.text.style.ReplacementSpan
    public void draw(Canvas canvas, CharSequence text, int i, int i2, float f, int i3, int i4, int i5, Paint paint) {
        Intrinsics.checkNotNullParameter(canvas, "canvas");
        Intrinsics.checkNotNullParameter(text, "text");
        Intrinsics.checkNotNullParameter(paint, "paint");
        canvas.save();
        Drawable drawable = this.a;
        if (drawable != null) {
            if (((DynamicDrawableSpan) this).mVerticalAlignment == 1) {
                i3 -= paint.getFontMetricsInt().descent;
            }
            canvas.translate(f, i3);
            Intrinsics.d(drawable);
            drawable.draw(canvas);
        }
        canvas.restore();
    }

    @Override // android.text.style.DynamicDrawableSpan
    public final Drawable getDrawable() {
        return this.a;
    }

    @Override // android.text.style.DynamicDrawableSpan, android.text.style.ReplacementSpan
    public final int getSize(Paint paint, CharSequence charSequence, int i, int i2, Paint.FontMetricsInt fontMetricsInt) {
        Rect rect;
        Rect rect2;
        AztecText aztecText;
        Rect rect3;
        AztecText aztecText2;
        Intrinsics.checkNotNullParameter(paint, "paint");
        WeakReference weakReference = this.b;
        Drawable drawable = this.a;
        if (weakReference == null || ((aztecText = (AztecText) weakReference.get()) != null && aztecText.getWidthMeasureSpec() == 0)) {
            if (drawable == null || (rect2 = drawable.getBounds()) == null) {
                rect2 = new Rect(0, 0, 0, 0);
            }
            rect = new Rect(rect2);
        } else {
            WeakReference weakReference2 = this.b;
            Layout layout = (weakReference2 == null || (aztecText2 = (AztecText) weakReference2.get()) == null) ? null : aztecText2.getLayout();
            if (layout == null) {
                rect = new Rect(0, 0, 0, 0);
            } else {
                int lineForOffset = layout.getLineForOffset(i);
                int paragraphRight = layout.getParagraphRight(lineForOffset) - layout.getParagraphLeft(lineForOffset);
                int intrinsicHeight = -1;
                int intrinsicWidth = (drawable != null ? drawable.getIntrinsicWidth() : -1) > -1 ? drawable != null ? drawable.getIntrinsicWidth() : -1 : paragraphRight;
                if ((drawable != null ? drawable.getIntrinsicHeight() : -1) <= -1) {
                    intrinsicHeight = (int) (intrinsicWidth / this.c);
                } else if (drawable != null) {
                    intrinsicHeight = drawable.getIntrinsicHeight();
                }
                if (intrinsicWidth > paragraphRight) {
                    intrinsicHeight = (int) (paragraphRight / this.c);
                } else {
                    paragraphRight = intrinsicWidth;
                }
                if (drawable != null) {
                    drawable.setBounds(new Rect(0, 0, paragraphRight, intrinsicHeight));
                }
                if (drawable == null || (rect3 = drawable.getBounds()) == null) {
                    rect3 = new Rect(0, 0, 0, 0);
                }
                rect = new Rect(rect3);
            }
        }
        if (fontMetricsInt != null && rect.height() > 0) {
            int i3 = -rect.height();
            fontMetricsInt.ascent = i3;
            fontMetricsInt.descent = 0;
            fontMetricsInt.top = i3;
            fontMetricsInt.bottom = 0;
        }
        return rect.width() > 0 ? rect.width() : super.getSize(paint, charSequence, i, i2, fontMetricsInt);
    }
}
