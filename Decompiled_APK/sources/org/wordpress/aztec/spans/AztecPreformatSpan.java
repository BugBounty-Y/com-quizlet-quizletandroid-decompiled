package org.wordpress.aztec.spans;

import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.CornerPathEffect;
import android.graphics.Paint;
import android.graphics.Path;
import android.text.Editable;
import android.text.Layout;
import android.text.SpannableStringBuilder;
import android.text.Spanned;
import android.text.TextPaint;
import android.text.style.LeadingMarginSpan;
import android.text.style.LineBackgroundSpan;
import android.text.style.LineHeightSpan;
import android.text.style.TypefaceSpan;
import com.google.android.gms.internal.mlkit_vision_camera.U2;
import com.google.android.gms.internal.mlkit_vision_camera.W2;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.wordpress.aztec.C5146b;

@Metadata
/* loaded from: classes3.dex */
public class AztecPreformatSpan extends TypefaceSpan implements D, LeadingMarginSpan, LineBackgroundSpan, LineHeightSpan {
    public int a;
    public final C5146b b;
    public org.wordpress.aztec.formatting.g c;
    public final String d;
    public int e;
    public int f;
    public int g;
    public int h;
    public int i;
    public int j;
    public final Paint k;
    public final Paint l;
    public final org.wordpress.aztec.x m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public AztecPreformatSpan(int i, C5146b attributes, org.wordpress.aztec.formatting.g preformatStyle) {
        super("monospace");
        Intrinsics.checkNotNullParameter(attributes, "attributes");
        Intrinsics.checkNotNullParameter(preformatStyle, "preformatStyle");
        this.a = i;
        this.b = attributes;
        this.c = preformatStyle;
        this.d = "pre";
        this.e = -1;
        this.f = -1;
        Paint paint = new Paint();
        paint.setAntiAlias(true);
        paint.setStyle(Paint.Style.STROKE);
        this.k = paint;
        Paint paint2 = new Paint();
        paint2.setAntiAlias(true);
        paint2.setStrokeCap(Paint.Cap.ROUND);
        this.l = paint2;
        this.m = org.wordpress.aztec.x.y;
    }

    @Override // org.wordpress.aztec.spans.K
    public int a() {
        return this.a;
    }

    @Override // org.wordpress.aztec.spans.O
    public final int b() {
        return this.f;
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
            this.g = i5;
            this.h = fm.top;
            this.i = fm.descent;
            this.j = fm.bottom;
            fm.ascent = i5 - v().d;
            fm.top -= v().d;
            if (!z2) {
                fm.descent = this.i;
                fm.bottom = this.j;
            }
        }
        if (z2) {
            fm.descent += v().d;
            fm.bottom += v().d;
            if (!z) {
                fm.ascent = this.g;
                fm.top = this.h;
            }
        }
        if (z || z2) {
            return;
        }
        fm.ascent = this.g;
        fm.top = this.h;
        fm.descent = this.i;
        fm.bottom = this.j;
    }

    @Override // android.text.style.LineBackgroundSpan
    public final void drawBackground(Canvas canvas, Paint paint, int i, int i2, int i3, int i4, int i5, CharSequence text, int i6, int i7, int i8) {
        Intrinsics.checkNotNullParameter(canvas, "canvas");
        Intrinsics.checkNotNullParameter(paint, "paint");
        Intrinsics.checkNotNullParameter(text, "text");
        Spanned spanned = (Spanned) text;
        int spanStart = spanned.getSpanStart(this);
        int spanEnd = spanned.getSpanEnd(this);
        boolean z = spanStart == i6;
        boolean z2 = spanEnd == i7;
        int i9 = (int) (v().b * 255);
        Paint paint2 = this.l;
        paint2.setColor(Color.argb(i9, Color.red(v().a), Color.green(v().a), Color.blue(v().a)));
        paint2.setPathEffect(new CornerPathEffect(v().g));
        Paint paint3 = this.k;
        paint3.setPathEffect(new CornerPathEffect(v().g));
        paint3.setColor(v().f);
        paint3.setStrokeWidth(v().h);
        Path path = new Path();
        if (z) {
            float f = i;
            float f2 = i5;
            path.moveTo(f, f2);
            float f3 = i3;
            path.lineTo(f, f3);
            float f4 = i2;
            path.lineTo(f4, f3);
            path.lineTo(f4, f2);
        } else if (z2) {
            float f5 = i;
            float f6 = i3;
            path.moveTo(f5, f6);
            float f7 = i5;
            path.lineTo(f5, f7);
            float f8 = i2;
            path.lineTo(f8, f7);
            path.lineTo(f8, f6);
        } else {
            paint2.setPathEffect(null);
            float f9 = i;
            float f10 = i3;
            path.moveTo(f9, f10);
            float f11 = i2;
            path.lineTo(f11, f10);
            float f12 = i5;
            path.lineTo(f11, f12);
            path.lineTo(f9, f12);
            path.lineTo(f9, f10);
        }
        canvas.drawPath(path, paint2);
        Path path2 = new Path();
        if (z) {
            float f13 = i;
            float f14 = i5;
            path2.moveTo(f13, f14);
            float f15 = i3;
            path2.lineTo(f13, f15);
            float f16 = i2;
            path2.lineTo(f16, f15);
            path2.lineTo(f16, f14);
            if (z2) {
                path2.lineTo(f13, f14);
            }
        } else if (z2) {
            float f17 = i;
            float f18 = i3;
            path2.moveTo(f17, f18);
            float f19 = i5;
            path2.lineTo(f17, f19);
            float f20 = i2;
            path2.lineTo(f20, f19);
            path2.lineTo(f20, f18);
        } else {
            float f21 = i;
            float f22 = i3;
            path2.moveTo(f21, f22);
            float f23 = i5;
            path2.lineTo(f21, f23);
            float f24 = i2;
            path2.moveTo(f24, f22);
            path2.lineTo(f24, f23);
        }
        canvas.drawPath(path2, paint3);
    }

    @Override // android.text.style.LeadingMarginSpan
    public final void drawLeadingMargin(Canvas canvas, Paint paint, int i, int i2, int i3, int i4, int i5, CharSequence text, int i6, int i7, boolean z, Layout layout) {
        Intrinsics.checkNotNullParameter(canvas, "canvas");
        Intrinsics.checkNotNullParameter(paint, "paint");
        Intrinsics.checkNotNullParameter(text, "text");
        Intrinsics.checkNotNullParameter(layout, "layout");
    }

    @Override // org.wordpress.aztec.spans.C
    public C5146b f() {
        return this.b;
    }

    @Override // org.wordpress.aztec.spans.M
    public final String g() {
        return u();
    }

    @Override // android.text.style.LeadingMarginSpan
    public final int getLeadingMargin(boolean z) {
        return v().e;
    }

    @Override // org.wordpress.aztec.spans.C
    public final void h(Editable editable, int i, int i2) {
        U2.b(this, (SpannableStringBuilder) editable, i, i2);
    }

    @Override // org.wordpress.aztec.spans.O
    public final int i() {
        return this.e;
    }

    @Override // org.wordpress.aztec.spans.O
    public final void j(int i) {
        this.f = i;
    }

    @Override // org.wordpress.aztec.spans.D
    public final org.wordpress.aztec.G l() {
        return this.m;
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
        this.e = i;
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
    public void t(int i) {
        this.a = i;
    }

    @Override // org.wordpress.aztec.spans.M
    public final String u() {
        return this.d;
    }

    @Override // android.text.style.TypefaceSpan, android.text.style.CharacterStyle
    public final void updateDrawState(TextPaint ds) {
        Intrinsics.checkNotNullParameter(ds, "ds");
        super.updateDrawState(ds);
        ds.setTextSize(v().i);
    }

    @Override // android.text.style.TypefaceSpan, android.text.style.MetricAffectingSpan
    public final void updateMeasureState(TextPaint paint) {
        Intrinsics.checkNotNullParameter(paint, "paint");
        super.updateMeasureState(paint);
        paint.setTextSize(v().i);
    }

    public org.wordpress.aztec.formatting.g v() {
        return this.c;
    }

    public void w(org.wordpress.aztec.formatting.g gVar) {
        Intrinsics.checkNotNullParameter(gVar, "<set-?>");
        this.c = gVar;
    }
}
