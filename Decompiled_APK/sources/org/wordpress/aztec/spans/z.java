package org.wordpress.aztec.spans;

import android.text.Editable;
import android.text.SpannableStringBuilder;
import com.google.android.gms.internal.mlkit_vision_camera.T2;
import com.google.android.gms.internal.mlkit_vision_camera.W2;
import kotlin.jvm.internal.Intrinsics;
import org.wordpress.aztec.C5146b;

/* loaded from: classes3.dex */
public class z implements L {
    public final C5146b a;
    public int b;
    public final String c;

    public z(String tag, C5146b attributes, int i) {
        Intrinsics.checkNotNullParameter(tag, "tag");
        Intrinsics.checkNotNullParameter(attributes, "attributes");
        this.a = attributes;
        this.b = i;
        this.c = tag;
    }

    @Override // org.wordpress.aztec.spans.K
    public final int a() {
        return this.b;
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
    public final void h(Editable editable, int i, int i2) {
        SpannableStringBuilder output = (SpannableStringBuilder) editable;
        Intrinsics.checkNotNullParameter(output, "output");
        Intrinsics.checkNotNullParameter(output, "output");
        T2.c(this, output, i, i2);
    }

    @Override // org.wordpress.aztec.spans.M
    public final String n() {
        return W2.a(this);
    }

    @Override // org.wordpress.aztec.spans.K
    public final void t(int i) {
        this.b = i;
    }

    @Override // org.wordpress.aztec.spans.M
    public final String u() {
        return this.c;
    }
}
