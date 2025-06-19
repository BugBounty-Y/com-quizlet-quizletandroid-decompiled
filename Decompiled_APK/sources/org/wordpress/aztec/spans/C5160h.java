package org.wordpress.aztec.spans;

import android.graphics.Paint;
import android.text.Editable;
import android.text.SpannableStringBuilder;
import android.text.Spanned;
import android.text.TextPaint;
import android.text.style.LineHeightSpan;
import android.text.style.MetricAffectingSpan;
import android.text.style.UpdateLayout;
import com.google.android.gms.internal.mlkit_vision_camera.L2;
import com.google.android.gms.internal.mlkit_vision_camera.U2;
import com.google.android.gms.internal.mlkit_vision_camera.W2;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.internal.Intrinsics;
import org.wordpress.aztec.C5146b;

/* renamed from: org.wordpress.aztec.spans.h, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public class C5160h extends MetricAffectingSpan implements I, LineHeightSpan, UpdateLayout {
    public int a;
    public final C5146b b;
    public org.wordpress.aztec.formatting.c c;
    public int d;
    public int e;
    public org.wordpress.aztec.G f;
    public EnumC5157e g;
    public Paint.FontMetricsInt h;
    public L2 i;
    public Float j;

    public C5160h(int i, org.wordpress.aztec.G textFormat, C5146b attributes, org.wordpress.aztec.formatting.c headerStyle) {
        Intrinsics.checkNotNullParameter(textFormat, "textFormat");
        Intrinsics.checkNotNullParameter(attributes, "attributes");
        Intrinsics.checkNotNullParameter(headerStyle, "headerStyle");
        this.a = i;
        this.b = attributes;
        this.c = headerStyle;
        this.d = -1;
        this.e = -1;
        this.f = org.wordpress.aztec.x.b;
        this.i = new C5158f(1.0f);
        y(textFormat);
    }

    @Override // org.wordpress.aztec.spans.K
    public int a() {
        return this.a;
    }

    @Override // org.wordpress.aztec.spans.O
    public final int b() {
        return this.e;
    }

    @Override // android.text.style.LineHeightSpan
    public final void chooseHeight(CharSequence text, int i, int i2, int i3, int i4, Paint.FontMetricsInt fm) {
        boolean z;
        Paint.FontMetricsInt fontMetricsInt;
        Paint.FontMetricsInt fontMetricsInt2;
        Intrinsics.checkNotNullParameter(text, "text");
        Intrinsics.checkNotNullParameter(fm, "fm");
        Spanned spanned = (Spanned) text;
        int spanStart = spanned.getSpanStart(this);
        int spanEnd = spanned.getSpanEnd(this);
        if (this.h == null) {
            Paint.FontMetricsInt fontMetricsInt3 = new Paint.FontMetricsInt();
            this.h = fontMetricsInt3;
            fontMetricsInt3.top = fm.top;
            fontMetricsInt3.ascent = fm.ascent;
            fontMetricsInt3.bottom = fm.bottom;
            fontMetricsInt3.descent = fm.descent;
        }
        int i5 = e().a;
        boolean z2 = true;
        if (i == spanStart || i < spanStart) {
            fm.ascent -= i5;
            fm.top -= i5;
            z = true;
        } else {
            z = false;
        }
        if (i2 == spanEnd || spanEnd < i2) {
            fm.descent += i5;
            fm.bottom += i5;
        } else {
            z2 = false;
        }
        if (!z && (fontMetricsInt2 = this.h) != null) {
            fm.ascent = fontMetricsInt2.ascent;
            fm.top = fontMetricsInt2.top;
        }
        if (z2 || (fontMetricsInt = this.h) == null) {
            return;
        }
        fm.descent = fontMetricsInt.descent;
        fm.bottom = fontMetricsInt.bottom;
    }

    public org.wordpress.aztec.formatting.c e() {
        return this.c;
    }

    @Override // org.wordpress.aztec.spans.C
    public C5146b f() {
        return this.b;
    }

    @Override // org.wordpress.aztec.spans.M
    public final String g() {
        return u();
    }

    @Override // org.wordpress.aztec.spans.C
    public final void h(Editable output, int i, int i2) {
        Intrinsics.checkNotNullParameter(output, "output");
        U2.b(this, (SpannableStringBuilder) output, i, i2);
    }

    @Override // org.wordpress.aztec.spans.O
    public final int i() {
        return this.d;
    }

    @Override // org.wordpress.aztec.spans.O
    public final void j(int i) {
        this.e = i;
    }

    public final EnumC5157e k() {
        EnumC5157e enumC5157e = this.g;
        if (enumC5157e != null) {
            return enumC5157e;
        }
        Intrinsics.m("heading");
        throw null;
    }

    @Override // org.wordpress.aztec.spans.D
    public final org.wordpress.aztec.G l() {
        return this.f;
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
    public void t(int i) {
        this.a = i;
    }

    public final String toString() {
        return "AztecHeadingSpan : " + k().b;
    }

    @Override // org.wordpress.aztec.spans.M
    public final String u() {
        return k().b;
    }

    /* JADX WARN: Removed duplicated region for block: B:16:0x0067  */
    /* JADX WARN: Type inference failed for: r0v7, types: [java.lang.Object, java.util.Map] */
    @Override // android.text.style.CharacterStyle
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void updateDrawState(android.text.TextPaint r3) {
        /*
            r2 = this;
            java.lang.String r0 = "textPaint"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r3, r0)
            com.google.android.gms.internal.mlkit_vision_camera.L2 r0 = r2.v()
            boolean r1 = r0 instanceof org.wordpress.aztec.spans.C5158f
            if (r1 == 0) goto L3c
            float r0 = r3.getTextSize()
            org.wordpress.aztec.spans.e r1 = r2.k()
            float r1 = r1.a
            float r0 = r0 * r1
            r3.setTextSize(r0)
            float r0 = r3.getTextSize()
            int r1 = r2.w()
            float r1 = (float) r1
            float r0 = r0 + r1
            r1 = 0
            int r0 = (r0 > r1 ? 1 : (r0 == r1 ? 0 : -1))
            if (r0 < 0) goto L38
            float r0 = r3.getTextSize()
            int r1 = r2.w()
            float r1 = (float) r1
            float r0 = r0 + r1
            r3.setTextSize(r0)
            goto L48
        L38:
            r3.setTextSize(r1)
            goto L48
        L3c:
            boolean r1 = r0 instanceof org.wordpress.aztec.spans.C5159g
            if (r1 == 0) goto L48
            org.wordpress.aztec.spans.g r0 = (org.wordpress.aztec.spans.C5159g) r0
            int r0 = r0.a
            float r0 = (float) r0
            r3.setTextSize(r0)
        L48:
            r0 = 1
            r3.setFakeBoldText(r0)
            org.wordpress.aztec.formatting.c r0 = r2.e()
            java.lang.Object r0 = r0.b
            org.wordpress.aztec.spans.e r1 = r2.k()
            java.lang.Object r0 = r0.get(r1)
            org.wordpress.aztec.formatting.b r0 = (org.wordpress.aztec.formatting.b) r0
            if (r0 == 0) goto L67
            int r0 = r0.c
            java.lang.Integer r1 = java.lang.Integer.valueOf(r0)
            if (r0 == 0) goto L67
            goto L68
        L67:
            r1 = 0
        L68:
            if (r1 == 0) goto L71
            int r0 = r1.intValue()
            r3.setColor(r0)
        L71:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: org.wordpress.aztec.spans.C5160h.updateDrawState(android.text.TextPaint):void");
    }

    /* JADX WARN: Type inference failed for: r0v6, types: [java.lang.Object, java.util.Map] */
    @Override // android.text.style.MetricAffectingSpan
    public final void updateMeasureState(TextPaint paint) {
        Intrinsics.checkNotNullParameter(paint, "paint");
        L2 l2V = v();
        Integer num = null;
        if (!l2V.equals(this.i) || !Intrinsics.a(this.j, paint.getFontSpacing())) {
            this.h = null;
        }
        this.i = l2V;
        this.j = Float.valueOf(paint.getFontSpacing());
        if (l2V instanceof C5158f) {
            paint.setTextSize(paint.getTextSize() * k().a);
            if (paint.getTextSize() + w() >= DefinitionKt.NO_Float_VALUE) {
                paint.setTextSize(paint.getTextSize() + w());
            } else {
                paint.setTextSize(DefinitionKt.NO_Float_VALUE);
            }
        } else if (l2V instanceof C5159g) {
            paint.setTextSize(((C5159g) l2V).a);
        }
        org.wordpress.aztec.formatting.b bVar = (org.wordpress.aztec.formatting.b) e().b.get(k());
        if (bVar != null) {
            int i = bVar.c;
            Integer numValueOf = Integer.valueOf(i);
            if (i != 0) {
                num = numValueOf;
            }
        }
        if (num != null) {
            paint.setColor(num.intValue());
        }
    }

    /* JADX WARN: Type inference failed for: r0v1, types: [java.lang.Object, java.util.Map] */
    public final L2 v() {
        org.wordpress.aztec.formatting.b bVar = (org.wordpress.aztec.formatting.b) e().b.get(k());
        if (bVar != null) {
            int i = bVar.a;
            Integer numValueOf = Integer.valueOf(i);
            if (i <= 0) {
                numValueOf = null;
            }
            if (numValueOf != null) {
                return new C5159g(w() + numValueOf.intValue());
            }
        }
        return new C5158f(k().a);
    }

    /* JADX WARN: Type inference failed for: r0v1, types: [java.lang.Object, java.util.Map] */
    public final int w() {
        org.wordpress.aztec.formatting.b bVar = (org.wordpress.aztec.formatting.b) e().b.get(k());
        if (bVar != null) {
            return bVar.b;
        }
        return 0;
    }

    public void x(org.wordpress.aztec.formatting.c cVar) {
        Intrinsics.checkNotNullParameter(cVar, "<set-?>");
        this.c = cVar;
    }

    public final void y(org.wordpress.aztec.G textFormat) {
        Intrinsics.checkNotNullParameter(textFormat, "value");
        this.f = textFormat;
        Intrinsics.checkNotNullParameter(textFormat, "textFormat");
        EnumC5157e enumC5157e = textFormat == org.wordpress.aztec.x.b ? EnumC5157e.c : textFormat == org.wordpress.aztec.x.c ? EnumC5157e.d : textFormat == org.wordpress.aztec.x.d ? EnumC5157e.e : textFormat == org.wordpress.aztec.x.e ? EnumC5157e.f : textFormat == org.wordpress.aztec.x.f ? EnumC5157e.g : textFormat == org.wordpress.aztec.x.g ? EnumC5157e.h : EnumC5157e.c;
        Intrinsics.checkNotNullParameter(enumC5157e, "<set-?>");
        this.g = enumC5157e;
    }
}
