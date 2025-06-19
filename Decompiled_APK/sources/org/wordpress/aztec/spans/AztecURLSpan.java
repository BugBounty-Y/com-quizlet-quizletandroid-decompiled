package org.wordpress.aztec.spans;

import android.text.Editable;
import android.text.TextPaint;
import android.text.style.URLSpan;
import com.google.android.gms.internal.mlkit_vision_camera.V2;
import com.google.android.gms.internal.mlkit_vision_camera.W2;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.wordpress.aztec.C5146b;

@Metadata
/* loaded from: classes3.dex */
public final class AztecURLSpan extends URLSpan implements H {
    public final String a;
    public org.wordpress.aztec.formatting.o b;
    public C5146b c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public AztecURLSpan(String url, C5146b attributes) {
        super(url);
        Intrinsics.checkNotNullParameter(url, "url");
        Intrinsics.checkNotNullParameter(attributes, "attributes");
        this.a = "a";
        this.b = new org.wordpress.aztec.formatting.o(0, true);
        this.c = new C5146b();
        Intrinsics.checkNotNullParameter(attributes, "<set-?>");
        this.c = attributes;
        if (attributes.a("href")) {
            return;
        }
        this.c.d("href", url);
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
        return this.a;
    }

    @Override // android.text.style.ClickableSpan, android.text.style.CharacterStyle
    public final void updateDrawState(TextPaint ds) {
        Intrinsics.checkNotNullParameter(ds, "ds");
        int i = this.b.a;
        if (i == 0) {
            i = ds.linkColor;
        }
        ds.setColor(i);
        ds.setUnderlineText(this.b.b);
    }
}
