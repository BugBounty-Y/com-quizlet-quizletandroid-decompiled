package org.wordpress.aztec.spans;

import android.graphics.Canvas;
import android.graphics.Paint;
import android.text.Layout;
import android.text.Spanned;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.wordpress.aztec.C5146b;

@Metadata
/* loaded from: classes3.dex */
public class AztecOrderedListSpan extends AztecListSpan {
    public int d;
    public final C5146b e;
    public org.wordpress.aztec.formatting.e f;
    public final String g;
    public int h;
    public float i;
    public final org.wordpress.aztec.x j;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public AztecOrderedListSpan(int i, C5146b attributes, org.wordpress.aztec.formatting.e listStyle) {
        super(listStyle.e);
        Intrinsics.checkNotNullParameter(attributes, "attributes");
        Intrinsics.checkNotNullParameter(listStyle, "listStyle");
        this.d = i;
        this.e = attributes;
        this.f = listStyle;
        this.g = "ol";
        this.j = org.wordpress.aztec.x.i;
    }

    @Override // org.wordpress.aztec.spans.AztecListSpan, org.wordpress.aztec.spans.K
    public final int a() {
        return this.d;
    }

    @Override // android.text.style.LeadingMarginSpan.Standard, android.text.style.LeadingMarginSpan
    public final void drawLeadingMargin(Canvas c, Paint p, int i, int i2, int i3, int i4, int i5, CharSequence text, int i6, int i7, boolean z, Layout l) throws NumberFormatException {
        int i8;
        String strF;
        Intrinsics.checkNotNullParameter(c, "c");
        Intrinsics.checkNotNullParameter(p, "p");
        Intrinsics.checkNotNullParameter(text, "text");
        Intrinsics.checkNotNullParameter(l, "l");
        if (z) {
            Spanned spanned = (Spanned) text;
            int spanStart = spanned.getSpanStart(this);
            int spanEnd = spanned.getSpanEnd(this);
            if (spanStart > i6 || i6 > spanEnd || spanStart > i7 || i7 > spanEnd) {
                return;
            }
            Paint.Style style = p.getStyle();
            int color = p.getColor();
            p.setColor(this.f.a);
            p.setStyle(Paint.Style.FILL);
            C5146b c5146b = this.e;
            if (c5146b.a("start")) {
                String value = c5146b.getValue("start");
                Intrinsics.checkNotNullExpressionValue(value, "getValue(...)");
                i8 = Integer.parseInt(value);
            } else {
                i8 = 0;
            }
            Integer numV = v(i7, text);
            if (numV != null) {
                int iIntValue = numV.intValue();
                boolean zA = c5146b.a("reversed");
                if (i8 > 0) {
                    iIntValue = zA ? i8 - (iIntValue - 1) : (iIntValue - 1) + i8;
                } else {
                    Intrinsics.checkNotNullParameter(text, "text");
                    Spanned spanned2 = (Spanned) text;
                    CharSequence charSequenceSubSequence = text.subSequence(spanned2.getSpanStart(this), spanned2.getSpanEnd(this));
                    Intrinsics.e(charSequenceSubSequence, "null cannot be cast to non-null type android.text.Spanned");
                    Spanned spanned3 = (Spanned) charSequenceSubSequence;
                    Object[] spans = spanned3.getSpans(0, spanned3.length(), C5164l.class);
                    Intrinsics.checkNotNullExpressionValue(spans, "getSpans(...)");
                    ArrayList arrayList = new ArrayList();
                    for (Object obj : spans) {
                        if (((C5164l) obj).a == a() + 1) {
                            arrayList.add(obj);
                        }
                    }
                    int size = arrayList.size();
                    if (zA) {
                        iIntValue = size - (iIntValue - 1);
                    }
                }
                if (i2 >= 0) {
                    StringBuilder sb = new StringBuilder();
                    sb.append(iIntValue);
                    sb.append('.');
                    strF = sb.toString();
                } else {
                    strF = android.support.v4.media.session.a.f(iIntValue, ".");
                }
            } else {
                strF = "";
            }
            float fMeasureText = p.measureText(strF);
            float fMax = Math.max(this.i, fMeasureText);
            this.i = fMax;
            float f = (this.f.b * i2 * 1.0f) + i;
            if (i2 == 1) {
                f -= fMeasureText;
            }
            if (f < DefinitionKt.NO_Float_VALUE) {
                this.h = -((int) f);
                f = 0.0f;
            }
            int i9 = this.h;
            if (i9 > 0 && fMeasureText < fMax) {
                f += i9;
            }
            c.drawText(strF, f, i4, p);
            p.setColor(color);
            p.setStyle(style);
        }
    }

    @Override // org.wordpress.aztec.spans.C
    public final C5146b f() {
        return this.e;
    }

    @Override // android.text.style.LeadingMarginSpan.Standard, android.text.style.LeadingMarginSpan
    public final int getLeadingMargin(boolean z) {
        org.wordpress.aztec.formatting.e eVar = this.f;
        return (eVar.d * 2) + eVar.b + eVar.c + this.h;
    }

    @Override // org.wordpress.aztec.spans.D
    public final org.wordpress.aztec.G l() {
        return this.j;
    }

    @Override // org.wordpress.aztec.spans.K
    public final void t(int i) {
        this.d = i;
    }

    @Override // org.wordpress.aztec.spans.M
    public final String u() {
        return this.g;
    }
}
