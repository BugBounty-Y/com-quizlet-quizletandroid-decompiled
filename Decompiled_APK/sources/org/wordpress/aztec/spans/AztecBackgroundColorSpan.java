package org.wordpress.aztec.spans;

import android.graphics.Color;
import android.text.Editable;
import android.text.TextPaint;
import android.text.style.BackgroundColorSpan;
import com.google.android.gms.internal.mlkit_vision_camera.V2;
import com.google.android.gms.internal.mlkit_vision_camera.W2;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.wordpress.aztec.C5146b;

@Metadata
/* loaded from: classes3.dex */
public final class AztecBackgroundColorSpan extends BackgroundColorSpan implements H {
    public final int a;
    public final int b;
    public C5146b c;
    public final String d;

    public AztecBackgroundColorSpan(int i) {
        super(i);
        this.a = i;
        this.b = 220;
        this.c = new C5146b();
        this.d = "span";
    }

    @Override // org.wordpress.aztec.spans.C
    public final C5146b f() {
        return this.c;
    }

    @Override // org.wordpress.aztec.spans.M
    public final String g() {
        return u();
    }

    @Override // org.wordpress.aztec.spans.C
    public final void h(Editable editable, int i, int i2) {
        V2.a(this, editable, i, i2);
    }

    @Override // org.wordpress.aztec.spans.M
    public final String n() {
        return W2.a(this);
    }

    @Override // org.wordpress.aztec.spans.C
    public final void r(C5146b c5146b) {
        Intrinsics.checkNotNullParameter(c5146b, "<set-?>");
        this.c = c5146b;
    }

    @Override // org.wordpress.aztec.spans.M
    public final String u() {
        return this.d;
    }

    @Override // android.text.style.BackgroundColorSpan, android.text.style.CharacterStyle
    public final void updateDrawState(TextPaint textPaint) {
        Intrinsics.checkNotNullParameter(textPaint, "textPaint");
        int i = this.a;
        textPaint.bgColor = Color.argb(this.b, Color.red(i), Color.green(i), Color.blue(i));
    }
}
