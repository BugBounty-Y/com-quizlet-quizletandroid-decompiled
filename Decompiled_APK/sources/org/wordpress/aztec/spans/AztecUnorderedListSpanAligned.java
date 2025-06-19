package org.wordpress.aztec.spans;

import android.text.Layout;
import kotlin.Metadata;

@Metadata
/* loaded from: classes3.dex */
public final class AztecUnorderedListSpanAligned extends AztecUnorderedListSpan implements B {
    public Layout.Alignment i;

    @Override // org.wordpress.aztec.spans.B
    public final void c(Layout.Alignment alignment) {
        this.i = alignment;
    }

    @Override // org.wordpress.aztec.spans.B
    public final Layout.Alignment d() {
        return this.i;
    }

    @Override // android.text.style.AlignmentSpan
    public final Layout.Alignment getAlignment() {
        Layout.Alignment alignmentD = d();
        return alignmentD == null ? Layout.Alignment.ALIGN_NORMAL : alignmentD;
    }
}
