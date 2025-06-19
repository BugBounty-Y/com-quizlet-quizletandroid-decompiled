package org.wordpress.aztec.spans;

import android.text.Layout;
import org.wordpress.aztec.C5146b;

/* loaded from: classes3.dex */
public final class y extends C5175x implements B {
    public C5146b f;
    public int g;
    public Layout.Alignment h;

    @Override // org.wordpress.aztec.spans.C5175x, org.wordpress.aztec.spans.K
    public final int a() {
        return this.g;
    }

    @Override // org.wordpress.aztec.spans.B
    public final void c(Layout.Alignment alignment) {
        this.h = alignment;
    }

    @Override // org.wordpress.aztec.spans.B
    public final Layout.Alignment d() {
        return this.h;
    }

    @Override // org.wordpress.aztec.spans.C5175x, org.wordpress.aztec.spans.C
    public final C5146b f() {
        return this.f;
    }

    @Override // android.text.style.AlignmentSpan
    public final Layout.Alignment getAlignment() {
        Layout.Alignment alignmentD = d();
        return alignmentD == null ? Layout.Alignment.ALIGN_NORMAL : alignmentD;
    }

    @Override // org.wordpress.aztec.spans.C5175x, org.wordpress.aztec.spans.K
    public final void t(int i) {
        this.g = i;
    }
}
