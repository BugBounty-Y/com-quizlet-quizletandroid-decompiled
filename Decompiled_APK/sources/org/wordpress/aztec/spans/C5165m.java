package org.wordpress.aztec.spans;

import android.text.Layout;

/* renamed from: org.wordpress.aztec.spans.m, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C5165m extends C5164l implements B {
    public Layout.Alignment g;

    @Override // org.wordpress.aztec.spans.B
    public final void c(Layout.Alignment alignment) {
        this.g = alignment;
    }

    @Override // org.wordpress.aztec.spans.B
    public final Layout.Alignment d() {
        return this.g;
    }

    @Override // android.text.style.AlignmentSpan
    public final Layout.Alignment getAlignment() {
        Layout.Alignment alignmentD = d();
        return alignmentD == null ? Layout.Alignment.ALIGN_NORMAL : alignmentD;
    }
}
