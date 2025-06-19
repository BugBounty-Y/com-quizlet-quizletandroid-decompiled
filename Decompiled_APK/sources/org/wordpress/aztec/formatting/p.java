package org.wordpress.aztec.formatting;

import android.text.Editable;
import androidx.compose.animation.core.J0;
import kotlin.Pair;
import kotlin.collections.C4933y;
import kotlin.jvm.internal.Intrinsics;
import org.wordpress.aztec.AztecText;
import org.wordpress.aztec.C5146b;
import org.wordpress.aztec.spans.AztecURLSpan;

/* loaded from: classes3.dex */
public final class p extends J0 {
    public final o c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public p(AztecText editor, o linkStyle) {
        super(editor);
        Intrinsics.checkNotNullParameter(editor, "editor");
        Intrinsics.checkNotNullParameter(linkStyle, "linkStyle");
        this.c = linkStyle;
    }

    public static void Y(boolean z, C5146b c5146b) {
        if (z) {
            c5146b.d("target", "_blank");
            c5146b.d("rel", "noopener");
            return;
        }
        c5146b.c("target");
        if (c5146b.a("rel") && Intrinsics.b(c5146b.getValue("rel"), "noopener")) {
            c5146b.c("rel");
        }
    }

    public final C5146b T(int i, int i2) {
        Object[] spans = u().getSpans(i2, i, AztecURLSpan.class);
        Intrinsics.checkNotNullExpressionValue(spans, "getSpans(...)");
        AztecURLSpan aztecURLSpan = (AztecURLSpan) C4933y.B(spans);
        return aztecURLSpan != null ? aztecURLSpan.c : new C5146b();
    }

    public final Pair U() {
        Editable editableU = u();
        AztecText aztecText = (AztecText) this.b;
        Object[] spans = editableU.getSpans(aztecText.getSelectionStart(), aztecText.getSelectionEnd(), AztecURLSpan.class);
        Intrinsics.checkNotNullExpressionValue(spans, "getSpans(...)");
        AztecURLSpan aztecURLSpan = (AztecURLSpan) C4933y.A(spans);
        int spanStart = u().getSpanStart(aztecURLSpan);
        int spanEnd = u().getSpanEnd(aztecURLSpan);
        return (aztecText.getSelectionStart() < spanStart || aztecText.getSelectionEnd() > spanEnd) ? new Pair(Integer.valueOf(aztecText.getSelectionStart()), Integer.valueOf(aztecText.getSelectionEnd())) : new Pair(Integer.valueOf(spanStart), Integer.valueOf(spanEnd));
    }

    public final boolean V() {
        Editable editableU = u();
        AztecText aztecText = (AztecText) this.b;
        AztecURLSpan[] aztecURLSpanArr = (AztecURLSpan[]) editableU.getSpans(aztecText.getSelectionStart(), aztecText.getSelectionEnd(), AztecURLSpan.class);
        Intrinsics.d(aztecURLSpanArr);
        return !(aztecURLSpanArr.length == 0);
    }

    public final void W(int i, int i2) {
        if (i >= i2) {
            return;
        }
        AztecURLSpan[] aztecURLSpanArr = (AztecURLSpan[]) u().getSpans(i, i2, AztecURLSpan.class);
        Intrinsics.d(aztecURLSpanArr);
        for (AztecURLSpan aztecURLSpan : aztecURLSpanArr) {
            u().removeSpan(aztecURLSpan);
        }
    }

    public final void X(Editable spannable, String url, int i, int i2, C5146b attributes) {
        Intrinsics.checkNotNullParameter(spannable, "spannable");
        Intrinsics.checkNotNullParameter(url, "link");
        Intrinsics.checkNotNullParameter(attributes, "attributes");
        Intrinsics.checkNotNullParameter(url, "url");
        o linkStyle = this.c;
        Intrinsics.checkNotNullParameter(linkStyle, "linkStyle");
        Intrinsics.checkNotNullParameter(attributes, "attributes");
        AztecURLSpan aztecURLSpan = new AztecURLSpan(url, attributes);
        aztecURLSpan.b = linkStyle;
        spannable.setSpan(aztecURLSpan, i, i2, 33);
    }
}
