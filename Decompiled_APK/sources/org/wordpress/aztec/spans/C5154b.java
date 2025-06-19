package org.wordpress.aztec.spans;

import android.graphics.Color;
import android.graphics.Typeface;
import android.text.Editable;
import android.text.TextPaint;
import android.text.style.MetricAffectingSpan;
import com.google.android.gms.internal.mlkit_vision_camera.V2;
import com.google.android.gms.internal.mlkit_vision_camera.W2;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.internal.Intrinsics;
import org.wordpress.aztec.C5146b;

/* renamed from: org.wordpress.aztec.spans.b, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C5154b extends MetricAffectingSpan implements F {
    public C5146b a;
    public final String b;
    public org.wordpress.aztec.formatting.j c;

    public C5154b(C5146b attributes) {
        Intrinsics.checkNotNullParameter(attributes, "attributes");
        this.a = attributes;
        this.b = "code";
        this.c = new org.wordpress.aztec.formatting.j(0, DefinitionKt.NO_Float_VALUE, 0);
    }

    public final void a(TextPaint textPaint) {
        int i = (int) (this.c.b * 255);
        textPaint.setTypeface(Typeface.MONOSPACE);
        textPaint.bgColor = Color.argb(i, Color.red(this.c.a), Color.green(this.c.a), Color.blue(this.c.a));
        textPaint.setColor(this.c.c);
    }

    @Override // org.wordpress.aztec.spans.C
    public final C5146b f() {
        return this.a;
    }

    @Override // org.wordpress.aztec.spans.M
    public final String g() {
        return u();
    }

    @Override // org.wordpress.aztec.spans.C
    public final void h(Editable output, int i, int i2) {
        Intrinsics.checkNotNullParameter(output, "output");
        V2.a(this, output, i, i2);
    }

    @Override // org.wordpress.aztec.spans.M
    public final String n() {
        return W2.a(this);
    }

    @Override // org.wordpress.aztec.spans.C
    public final void r(C5146b c5146b) {
        Intrinsics.checkNotNullParameter(c5146b, "<set-?>");
        this.a = c5146b;
    }

    @Override // org.wordpress.aztec.spans.M
    public final String u() {
        return this.b;
    }

    @Override // android.text.style.CharacterStyle
    public final void updateDrawState(TextPaint tp) {
        Intrinsics.checkNotNullParameter(tp, "tp");
        a(tp);
    }

    @Override // android.text.style.MetricAffectingSpan
    public final void updateMeasureState(TextPaint tp) {
        Intrinsics.checkNotNullParameter(tp, "tp");
        a(tp);
    }
}
