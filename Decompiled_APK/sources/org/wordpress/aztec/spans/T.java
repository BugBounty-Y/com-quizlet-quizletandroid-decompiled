package org.wordpress.aztec.spans;

import android.graphics.Paint;
import android.text.Editable;
import android.text.SpannableStringBuilder;
import android.text.Spanned;
import android.text.style.LineHeightSpan;
import com.google.android.gms.internal.mlkit_vision_camera.U2;
import com.google.android.gms.internal.mlkit_vision_camera.W2;
import kotlin.jvm.internal.Intrinsics;
import org.wordpress.aztec.C5146b;

/* loaded from: classes3.dex */
public class T implements D, LineHeightSpan {
    public int a;
    public final C5146b b;
    public org.wordpress.aztec.formatting.f c;
    public boolean d;
    public int e;
    public int f;
    public final org.wordpress.aztec.x g;

    public T(int i, C5146b attributes, org.wordpress.aztec.formatting.f paragraphStyle) {
        Intrinsics.checkNotNullParameter(attributes, "attributes");
        Intrinsics.checkNotNullParameter(paragraphStyle, "paragraphStyle");
        this.a = i;
        this.b = attributes;
        this.c = paragraphStyle;
        this.e = -1;
        this.f = -1;
        this.g = org.wordpress.aztec.x.x;
    }

    @Override // org.wordpress.aztec.spans.K
    public final int a() {
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
        boolean zB = i > 1 ? Intrinsics.b(text.subSequence(i - 1, i).toString(), "\n") : false;
        boolean zB2 = i2 < text.length() ? Intrinsics.b(text.subSequence(i2, i2 + 1).toString(), "\n") : false;
        boolean z = i <= spanStart || zB;
        boolean z2 = spanEnd <= i2 || zB2;
        if (z) {
            this.d = true;
            int i5 = fm.ascent;
            int i6 = this.c.a;
            fm.ascent = i5 - i6;
            fm.top -= i6;
        }
        if (z2) {
            int i7 = fm.descent;
            int i8 = this.c.a;
            fm.descent = i7 + i8;
            fm.bottom += i8;
            this.d = false;
        }
        if (z || z2 || !this.d) {
            return;
        }
        this.d = false;
        int i9 = fm.ascent;
        int i10 = this.c.a;
        int i11 = i9 + i10;
        if (i11 < 0) {
            fm.ascent = i11;
        }
        int i12 = fm.top + i10;
        if (i12 < 0) {
            fm.top = i12;
        }
    }

    @Override // org.wordpress.aztec.spans.C
    public final C5146b f() {
        return this.b;
    }

    @Override // org.wordpress.aztec.spans.M
    public final String g() {
        return "p";
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
        return this.g;
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
    public final void t(int i) {
        this.a = i;
    }

    @Override // org.wordpress.aztec.spans.M
    public final String u() {
        return "p";
    }
}
