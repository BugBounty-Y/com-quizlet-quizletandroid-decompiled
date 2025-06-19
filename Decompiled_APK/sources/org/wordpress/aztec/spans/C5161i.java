package org.wordpress.aztec.spans;

import android.text.Layout;
import kotlin.jvm.internal.Intrinsics;
import org.wordpress.aztec.C5146b;

/* renamed from: org.wordpress.aztec.spans.i, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C5161i extends C5160h implements B {
    public int k;
    public C5146b l;
    public org.wordpress.aztec.formatting.c m;
    public Layout.Alignment n;

    @Override // org.wordpress.aztec.spans.C5160h, org.wordpress.aztec.spans.K
    public final int a() {
        return this.k;
    }

    @Override // org.wordpress.aztec.spans.B
    public final void c(Layout.Alignment alignment) {
        this.n = alignment;
    }

    @Override // org.wordpress.aztec.spans.B
    public final Layout.Alignment d() {
        return this.n;
    }

    @Override // org.wordpress.aztec.spans.C5160h
    public final org.wordpress.aztec.formatting.c e() {
        return this.m;
    }

    @Override // org.wordpress.aztec.spans.C5160h, org.wordpress.aztec.spans.C
    public final C5146b f() {
        return this.l;
    }

    @Override // android.text.style.AlignmentSpan
    public final Layout.Alignment getAlignment() {
        Layout.Alignment alignmentD = d();
        return alignmentD == null ? Layout.Alignment.ALIGN_NORMAL : alignmentD;
    }

    @Override // org.wordpress.aztec.spans.C5160h, org.wordpress.aztec.spans.K
    public final void t(int i) {
        this.k = i;
    }

    @Override // org.wordpress.aztec.spans.C5160h
    public final void x(org.wordpress.aztec.formatting.c cVar) {
        Intrinsics.checkNotNullParameter(cVar, "<set-?>");
        this.m = cVar;
    }
}
