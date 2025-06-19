package org.wordpress.aztec.spans;

import android.text.Layout;
import kotlin.jvm.internal.Intrinsics;
import org.wordpress.aztec.C5146b;

/* loaded from: classes3.dex */
public final class U extends T implements B {
    public Layout.Alignment h;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public U(int i, C5146b attributes, Layout.Alignment alignment, org.wordpress.aztec.formatting.f paragraphStyle) {
        super(i, attributes, paragraphStyle);
        Intrinsics.checkNotNullParameter(attributes, "attributes");
        Intrinsics.checkNotNullParameter(paragraphStyle, "paragraphStyle");
        this.h = alignment;
    }

    @Override // org.wordpress.aztec.spans.B
    public final void c(Layout.Alignment alignment) {
        this.h = alignment;
    }

    @Override // org.wordpress.aztec.spans.B
    public final Layout.Alignment d() {
        return this.h;
    }

    @Override // android.text.style.AlignmentSpan
    public final Layout.Alignment getAlignment() {
        Layout.Alignment alignmentD = d();
        return alignmentD == null ? Layout.Alignment.ALIGN_NORMAL : alignmentD;
    }
}
