package org.wordpress.aztec.spans;

import android.content.Context;
import android.text.Layout;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.wordpress.aztec.C5146b;

@Metadata
/* loaded from: classes3.dex */
public final class AztecTaskListSpanAligned extends AztecTaskListSpan implements B {
    public Layout.Alignment l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public AztecTaskListSpanAligned(int i, C5146b attributes, Context context, org.wordpress.aztec.formatting.e listStyle, Layout.Alignment alignment) {
        super(i, attributes, context, listStyle);
        Intrinsics.checkNotNullParameter(attributes, "attributes");
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(listStyle, "listStyle");
        this.l = alignment;
    }

    @Override // org.wordpress.aztec.spans.B
    public final void c(Layout.Alignment alignment) {
        this.l = alignment;
    }

    @Override // org.wordpress.aztec.spans.B
    public final Layout.Alignment d() {
        return this.l;
    }

    @Override // android.text.style.AlignmentSpan
    public final Layout.Alignment getAlignment() {
        Layout.Alignment alignmentD = d();
        return alignmentD == null ? Layout.Alignment.ALIGN_NORMAL : alignmentD;
    }
}
