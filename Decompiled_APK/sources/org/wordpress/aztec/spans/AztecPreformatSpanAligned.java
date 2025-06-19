package org.wordpress.aztec.spans;

import android.text.Layout;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.wordpress.aztec.C5146b;

@Metadata
/* loaded from: classes3.dex */
public final class AztecPreformatSpanAligned extends AztecPreformatSpan implements B {
    public int n;
    public C5146b o;
    public org.wordpress.aztec.formatting.g p;
    public Layout.Alignment q;

    @Override // org.wordpress.aztec.spans.AztecPreformatSpan, org.wordpress.aztec.spans.K
    public final int a() {
        return this.n;
    }

    @Override // org.wordpress.aztec.spans.B
    public final void c(Layout.Alignment alignment) {
        this.q = alignment;
    }

    @Override // org.wordpress.aztec.spans.B
    public final Layout.Alignment d() {
        return this.q;
    }

    @Override // org.wordpress.aztec.spans.AztecPreformatSpan, org.wordpress.aztec.spans.C
    public final C5146b f() {
        return this.o;
    }

    @Override // android.text.style.AlignmentSpan
    public final Layout.Alignment getAlignment() {
        Layout.Alignment alignmentD = d();
        return alignmentD == null ? Layout.Alignment.ALIGN_NORMAL : alignmentD;
    }

    @Override // org.wordpress.aztec.spans.AztecPreformatSpan, org.wordpress.aztec.spans.K
    public final void t(int i) {
        this.n = i;
    }

    @Override // org.wordpress.aztec.spans.AztecPreformatSpan
    public final org.wordpress.aztec.formatting.g v() {
        return this.p;
    }

    @Override // org.wordpress.aztec.spans.AztecPreformatSpan
    public final void w(org.wordpress.aztec.formatting.g gVar) {
        Intrinsics.checkNotNullParameter(gVar, "<set-?>");
        this.p = gVar;
    }
}
