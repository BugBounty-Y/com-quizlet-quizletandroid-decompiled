package org.wordpress.aztec.spans;

import android.text.style.ClickableSpan;
import android.view.View;
import kotlin.jvm.internal.Intrinsics;
import org.wordpress.aztec.AztecText;

/* loaded from: classes3.dex */
public final class V extends ClickableSpan {
    public final X a;

    public V(X unknownHtmlSpan) {
        Intrinsics.checkNotNullParameter(unknownHtmlSpan, "unknownHtmlSpan");
        this.a = unknownHtmlSpan;
    }

    @Override // android.text.style.ClickableSpan
    public final void onClick(View widget) {
        Intrinsics.checkNotNullParameter(widget, "widget");
        X unknownHtmlSpan = this.a;
        W w = unknownHtmlSpan.c;
        if (w != null) {
            Intrinsics.checkNotNullParameter(unknownHtmlSpan, "unknownHtmlSpan");
            ((AztecText) w).p(unknownHtmlSpan, "");
        }
    }
}
