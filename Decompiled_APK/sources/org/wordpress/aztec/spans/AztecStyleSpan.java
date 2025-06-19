package org.wordpress.aztec.spans;

import android.text.Editable;
import android.text.style.StyleSpan;
import com.google.android.gms.internal.mlkit_vision_camera.V2;
import com.google.android.gms.internal.mlkit_vision_camera.W2;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.wordpress.aztec.C5146b;

@Metadata
/* loaded from: classes3.dex */
public class AztecStyleSpan extends StyleSpan implements H {
    public C5146b a;
    public final kotlin.u b;

    public /* synthetic */ AztecStyleSpan(int i) {
        this(i, new C5146b());
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

    public String u() {
        return (String) this.b.getValue();
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public AztecStyleSpan(int i, C5146b attributes) {
        super(i);
        Intrinsics.checkNotNullParameter(attributes, "attributes");
        this.a = attributes;
        this.b = kotlin.l.b(new androidx.compose.foundation.lazy.C(i, 2));
    }
}
