package org.wordpress.aztec.spans;

import android.text.Layout;

/* renamed from: org.wordpress.aztec.spans.q, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C5169q extends C5168p implements B {
    public Layout.Alignment o;

    @Override // org.wordpress.aztec.spans.B
    public final void c(Layout.Alignment alignment) {
        this.o = alignment;
    }

    @Override // org.wordpress.aztec.spans.B
    public final Layout.Alignment d() {
        return this.o;
    }

    @Override // android.text.style.AlignmentSpan
    public final Layout.Alignment getAlignment() {
        Layout.Alignment alignmentD = d();
        return alignmentD == null ? Layout.Alignment.ALIGN_NORMAL : alignmentD;
    }
}
