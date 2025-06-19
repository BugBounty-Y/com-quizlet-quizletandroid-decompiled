package org.wordpress.aztec.spans;

import android.text.style.ClickableSpan;
import android.view.View;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: org.wordpress.aztec.spans.n, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C5166n extends ClickableSpan {
    public final AbstractC5167o a;

    public C5166n(AbstractC5167o mediaSpan) {
        Intrinsics.checkNotNullParameter(mediaSpan, "mediaSpan");
        this.a = mediaSpan;
    }

    @Override // android.text.style.ClickableSpan
    public final void onClick(View view) {
        Intrinsics.checkNotNullParameter(view, "view");
        this.a.getClass();
    }
}
