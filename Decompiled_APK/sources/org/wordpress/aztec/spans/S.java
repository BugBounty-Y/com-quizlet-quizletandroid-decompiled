package org.wordpress.aztec.spans;

import android.graphics.Color;
import android.text.Editable;
import android.text.TextPaint;
import android.text.style.CharacterStyle;
import com.google.android.gms.internal.mlkit_vision_camera.H2;
import com.google.android.gms.internal.mlkit_vision_camera.V2;
import com.google.android.gms.internal.mlkit_vision_camera.W2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;
import org.wordpress.aztec.C5146b;

/* loaded from: classes3.dex */
public final class S extends CharacterStyle implements H {
    public final String a;
    public C5146b b;
    public final Integer c;

    public S(C5146b attributes) {
        Integer numValueOf;
        Intrinsics.checkNotNullParameter(attributes, "attributes");
        this.a = "mark";
        this.b = new C5146b();
        Intrinsics.checkNotNullParameter(attributes, "<set-?>");
        this.b = attributes;
        String strD = H2.d("color", attributes);
        if (StringsKt.O(strD)) {
            numValueOf = null;
        } else {
            try {
                numValueOf = Integer.valueOf(Color.parseColor(strD));
            } catch (IllegalArgumentException unused) {
            }
        }
        this.c = numValueOf;
    }

    @Override // org.wordpress.aztec.spans.C
    public final C5146b f() {
        return this.b;
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
        this.b = c5146b;
    }

    @Override // org.wordpress.aztec.spans.M
    public final String u() {
        return this.a;
    }

    @Override // android.text.style.CharacterStyle
    public final void updateDrawState(TextPaint tp) {
        Intrinsics.checkNotNullParameter(tp, "tp");
        Integer num = this.c;
        if (num != null) {
            tp.setColor(num.intValue());
        }
    }

    public S(String str, C5146b attributes) {
        Integer numValueOf;
        Intrinsics.checkNotNullParameter(attributes, "attributes");
        this.a = "mark";
        this.b = new C5146b();
        Intrinsics.checkNotNullParameter(attributes, "<set-?>");
        this.b = attributes;
        if (str == null || StringsKt.O(str)) {
            numValueOf = null;
        } else {
            try {
                numValueOf = Integer.valueOf(Color.parseColor(str));
            } catch (IllegalArgumentException unused) {
            }
        }
        this.c = numValueOf;
    }
}
