package org.wordpress.aztec.spans;

import android.text.Editable;
import android.text.style.SuperscriptSpan;
import com.google.android.gms.internal.mlkit_vision_camera.V2;
import com.google.android.gms.internal.mlkit_vision_camera.W2;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.wordpress.aztec.C5146b;

@Metadata
/* loaded from: classes3.dex */
public final class AztecSuperscriptSpan extends SuperscriptSpan implements H {
    public C5146b a;
    public final String b;

    public AztecSuperscriptSpan(C5146b attributes) {
        Intrinsics.checkNotNullParameter(attributes, "attributes");
        this.a = attributes;
        this.b = "sup";
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
        V2.a(this, editable, i, i2);
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
}
