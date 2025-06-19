package org.wordpress.aztec.spans;

import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.Rect;
import android.text.Editable;
import android.text.Layout;
import android.text.SpannableStringBuilder;
import android.text.Spanned;
import android.text.TextPaint;
import android.text.TextUtils;
import android.text.style.CharacterStyle;
import android.text.style.LeadingMarginSpan;
import android.text.style.LineBackgroundSpan;
import android.text.style.LineHeightSpan;
import android.text.style.UpdateAppearance;
import android.text.style.UpdateLayout;
import androidx.collection.C0208f;
import com.google.android.gms.internal.mlkit_vision_camera.U2;
import com.google.android.gms.internal.mlkit_vision_camera.W2;
import java.util.Locale;
import kotlin.jvm.internal.Intrinsics;
import org.wordpress.aztec.C5146b;

/* renamed from: org.wordpress.aztec.spans.p, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public class C5168p extends CharacterStyle implements LeadingMarginSpan, LineBackgroundSpan, D, LineHeightSpan, UpdateLayout, UpdateAppearance {
    public int a;
    public final C5146b b;
    public org.wordpress.aztec.formatting.h c;
    public int d;
    public int e;
    public final Rect f;
    public int g;
    public final C0208f h;
    public final String i;
    public int j;
    public int k;
    public int l;
    public int m;
    public final org.wordpress.aztec.x n;

    public C5168p(int i, C5146b attributes, org.wordpress.aztec.formatting.h quoteStyle) {
        Intrinsics.checkNotNullParameter(attributes, "attributes");
        Intrinsics.checkNotNullParameter(quoteStyle, "quoteStyle");
        this.a = i;
        this.b = attributes;
        this.c = quoteStyle;
        this.d = -1;
        this.e = -1;
        this.f = new Rect();
        this.h = new C0208f(0);
        this.i = "blockquote";
        this.n = org.wordpress.aztec.x.u;
    }

    @Override // org.wordpress.aztec.spans.K
    public final int a() {
        return this.a;
    }

    @Override // org.wordpress.aztec.spans.O
    public final int b() {
        return this.e;
    }

    @Override // android.text.style.LineHeightSpan
    public final void chooseHeight(CharSequence text, int i, int i2, int i3, int i4, Paint.FontMetricsInt fm) {
        Intrinsics.checkNotNullParameter(text, "text");
        Intrinsics.checkNotNullParameter(fm, "fm");
        Spanned spanned = (Spanned) text;
        int spanStart = spanned.getSpanStart(this);
        int spanEnd = spanned.getSpanEnd(this);
        boolean z = i <= spanStart;
        boolean z2 = spanEnd <= i2;
        if (z) {
            int i5 = fm.ascent;
            this.j = i5;
            int i6 = fm.top;
            this.k = i6;
            int i7 = fm.descent;
            this.l = i7;
            int i8 = fm.bottom;
            this.m = i8;
            int i9 = this.c.h;
            fm.ascent = i5 - i9;
            fm.top = i6 - i9;
            if (!z2) {
                fm.descent = i7;
                fm.bottom = i8;
            }
        }
        if (z2) {
            int i10 = fm.descent;
            int i11 = this.c.h;
            fm.descent = i10 + i11;
            fm.bottom += i11;
            if (!z) {
                fm.ascent = this.j;
                fm.top = this.k;
            }
        }
        if (z || z2) {
            return;
        }
        fm.ascent = this.j;
        fm.top = this.k;
        fm.descent = this.l;
        fm.bottom = this.m;
    }

    @Override // android.text.style.LineBackgroundSpan
    public final void drawBackground(Canvas c, Paint p, int i, int i2, int i3, int i4, int i5, CharSequence text, int i6, int i7, int i8) {
        Intrinsics.checkNotNullParameter(c, "c");
        Intrinsics.checkNotNullParameter(p, "p");
        Intrinsics.checkNotNullParameter(text, "text");
        int i9 = (int) (this.c.d * 255);
        int color = p.getColor();
        p.setColor(Color.argb(i9, Color.red(this.c.a), Color.green(this.c.a), Color.blue(this.c.a)));
        boolean zT = (TextUtils.getLayoutDirectionFromLocale(Locale.getDefault()) == 1 ? androidx.core.text.f.d : androidx.core.text.f.c).t(text, i6, i7 - i6);
        C0208f c0208f = this.h;
        if (zT) {
            Float f = (Float) c0208f.get(Integer.valueOf(i6));
            i2 = f != null ? (int) f.floatValue() : 0;
        } else {
            Float f2 = (Float) c0208f.get(Integer.valueOf(i6));
            i = f2 != null ? (int) f2.floatValue() : 0;
        }
        Rect rect = this.f;
        rect.set(i, i3, i2, i5);
        c.drawRect(rect, p);
        p.setColor(color);
    }

    @Override // android.text.style.LeadingMarginSpan
    public final void drawLeadingMargin(Canvas c, Paint p, int i, int i2, int i3, int i4, int i5, CharSequence text, int i6, int i7, boolean z, Layout layout) {
        boolean z2;
        int i8;
        float f;
        float f2;
        Intrinsics.checkNotNullParameter(c, "c");
        Intrinsics.checkNotNullParameter(p, "p");
        Intrinsics.checkNotNullParameter(text, "text");
        Intrinsics.checkNotNullParameter(layout, "layout");
        Paint.Style style = p.getStyle();
        int color = p.getColor();
        p.setStyle(Paint.Style.FILL);
        p.setColor(this.c.b);
        Object[] spans = ((Editable) text).getSpans(i6, i7, C5164l.class);
        Intrinsics.checkNotNullExpressionValue(spans, "getSpans(...)");
        int length = spans.length;
        int i9 = 0;
        while (true) {
            if (i9 >= length) {
                z2 = false;
                break;
            } else {
                if (((C5164l) spans[i9]).a == this.a - 1) {
                    z2 = true;
                    break;
                }
                i9++;
            }
        }
        boolean zT = (TextUtils.getLayoutDirectionFromLocale(Locale.getDefault()) == 1 ? androidx.core.text.f.d : androidx.core.text.f.c).t(text, i6, i7 - i6);
        if (z2) {
            this.g = this.c.e;
            i8 = i;
        } else {
            i8 = zT ? i - this.c.e : this.c.e + i;
            this.g = 0;
        }
        C0208f c0208f = this.h;
        if (zT) {
            f = (this.c.g * i2) + i8;
            f2 = i8;
            c0208f.put(Integer.valueOf(i6), Float.valueOf(f));
        } else {
            f = i8;
            f2 = (this.c.g * i2) + i8;
            c0208f.put(Integer.valueOf(i6), Float.valueOf(f2));
        }
        c.drawRect(f, i3, f2, i5, p);
        p.setStyle(style);
        p.setColor(color);
    }

    @Override // org.wordpress.aztec.spans.C
    public final C5146b f() {
        return this.b;
    }

    @Override // org.wordpress.aztec.spans.M
    public final String g() {
        return u();
    }

    @Override // android.text.style.LeadingMarginSpan
    public final int getLeadingMargin(boolean z) {
        org.wordpress.aztec.formatting.h hVar = this.c;
        return ((hVar.e + hVar.g) + hVar.f) - this.g;
    }

    @Override // org.wordpress.aztec.spans.C
    public final void h(Editable editable, int i, int i2) {
        U2.b(this, (SpannableStringBuilder) editable, i, i2);
    }

    @Override // org.wordpress.aztec.spans.O
    public final int i() {
        return this.d;
    }

    @Override // org.wordpress.aztec.spans.O
    public final void j(int i) {
        this.e = i;
    }

    @Override // org.wordpress.aztec.spans.D
    public final org.wordpress.aztec.G l() {
        return this.n;
    }

    @Override // org.wordpress.aztec.spans.O
    public final boolean m() {
        return i() != -1;
    }

    @Override // org.wordpress.aztec.spans.M
    public final String n() {
        return W2.a(this);
    }

    @Override // org.wordpress.aztec.spans.O
    public final void o() {
        j(-1);
    }

    @Override // org.wordpress.aztec.spans.O
    public final void p(int i) {
        this.d = i;
    }

    @Override // org.wordpress.aztec.spans.O
    public final void q() {
        p(-1);
    }

    @Override // org.wordpress.aztec.spans.O
    public final boolean s() {
        return b() != -1;
    }

    @Override // org.wordpress.aztec.spans.K
    public final void t(int i) {
        this.a = i;
    }

    @Override // org.wordpress.aztec.spans.M
    public final String u() {
        return this.i;
    }

    @Override // android.text.style.CharacterStyle
    public final void updateDrawState(TextPaint textPaint) {
        if (textPaint == null) {
            return;
        }
        textPaint.setColor(this.c.c);
    }
}
