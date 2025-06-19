package org.wordpress.aztec.spans;

import android.graphics.Paint;
import android.text.Editable;
import android.text.SpannableStringBuilder;
import android.text.Spanned;
import android.text.style.LeadingMarginSpan;
import android.text.style.LineHeightSpan;
import android.text.style.UpdateLayout;
import com.google.android.gms.internal.mlkit_vision_camera.C2;
import com.google.android.gms.internal.mlkit_vision_camera.U2;
import com.google.android.gms.internal.mlkit_vision_camera.W2;
import java.util.ArrayList;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;

@Metadata
/* loaded from: classes3.dex */
public abstract class AztecListSpan extends LeadingMarginSpan.Standard implements LineHeightSpan, UpdateLayout, D {
    public final int a;
    public int b;
    public int c;

    public AztecListSpan(int i) {
        super(0);
        this.a = i;
        this.b = -1;
        this.c = -1;
    }

    @Override // org.wordpress.aztec.spans.K
    public abstract int a();

    @Override // org.wordpress.aztec.spans.O
    public final int b() {
        return this.c;
    }

    @Override // android.text.style.LineHeightSpan
    public final void chooseHeight(CharSequence text, int i, int i2, int i3, int i4, Paint.FontMetricsInt fm) {
        Intrinsics.checkNotNullParameter(text, "text");
        Intrinsics.checkNotNullParameter(fm, "fm");
        Spanned spanned = (Spanned) text;
        int spanStart = spanned.getSpanStart(this);
        int spanEnd = spanned.getSpanEnd(this);
        int i5 = this.a;
        if (i == spanStart || i < spanStart) {
            fm.ascent -= i5;
            fm.top -= i5;
        }
        if (i2 == spanEnd || spanEnd < i2) {
            fm.descent += i5;
            fm.bottom += i5;
        }
    }

    @Override // org.wordpress.aztec.spans.M
    public final String g() {
        return u();
    }

    @Override // org.wordpress.aztec.spans.C
    public final void h(Editable editable, int i, int i2) {
        U2.b(this, (SpannableStringBuilder) editable, i, i2);
    }

    @Override // org.wordpress.aztec.spans.O
    public final int i() {
        return this.b;
    }

    @Override // org.wordpress.aztec.spans.O
    public final void j(int i) {
        this.c = i;
    }

    @Override // org.wordpress.aztec.spans.O
    public final boolean m() {
        return i() != -1;
    }

    @Override // org.wordpress.aztec.spans.M
    public String n() {
        return W2.a(this);
    }

    @Override // org.wordpress.aztec.spans.O
    public final void o() {
        j(-1);
    }

    @Override // org.wordpress.aztec.spans.O
    public final void p(int i) {
        this.b = i;
    }

    @Override // org.wordpress.aztec.spans.O
    public final void q() {
        p(-1);
    }

    @Override // org.wordpress.aztec.spans.O
    public final boolean s() {
        return b() != -1;
    }

    public final Integer v(int i, CharSequence text) {
        Intrinsics.checkNotNullParameter(text, "text");
        Spanned spanned = (Spanned) text;
        int spanStart = spanned.getSpanStart(this);
        CharSequence charSequenceSubSequence = text.subSequence(spanStart, spanned.getSpanEnd(this));
        Intrinsics.e(charSequenceSubSequence, "null cannot be cast to non-null type android.text.Spanned");
        Spanned spanned2 = (Spanned) charSequenceSubSequence;
        int i2 = i - spanStart;
        int i3 = i2 - 1;
        if (i3 >= 0 && i2 <= spanned2.length()) {
            Object[] spans = spanned2.getSpans(i3, i2, AztecListSpan.class);
            Intrinsics.checkNotNullExpressionValue(spans, "getSpans(...)");
            for (Object obj : spans) {
                if (((AztecListSpan) obj).a() > a()) {
                    return null;
                }
            }
        }
        CharSequence charSequenceSubSequence2 = spanned2.subSequence(0, i2);
        Intrinsics.e(charSequenceSubSequence2, "null cannot be cast to non-null type android.text.Spanned");
        Spanned spanned3 = (Spanned) charSequenceSubSequence2;
        int iP = StringsKt.P(spanned3, C2.g, 0, 6) + 1;
        Object[] spans2 = spanned2.getSpans(0, spanned2.length(), C5164l.class);
        Intrinsics.checkNotNullExpressionValue(spans2, "getSpans(...)");
        for (Object obj2 : spans2) {
            C5164l c5164l = (C5164l) obj2;
            if (c5164l.a == a() + 1 && spanned2.getSpanStart(c5164l) == iP) {
                Object[] spans3 = spanned2.getSpans(0, Math.min(spanned3.length() + 1, spanned2.length()), C5164l.class);
                Intrinsics.checkNotNullExpressionValue(spans3, "getSpans(...)");
                ArrayList arrayList = new ArrayList();
                for (Object obj3 : spans3) {
                    if (((C5164l) obj3).a == a() + 1) {
                        arrayList.add(obj3);
                    }
                }
                return Integer.valueOf(arrayList.size());
            }
        }
        return null;
    }
}
