package com.quizlet.richtext.ui;

import android.content.Context;
import android.util.AttributeSet;
import android.widget.TextView;
import com.quizlet.partskit.widgets.QTextView;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes3.dex */
public class e extends QTextView {
    public com.quizlet.richtext.rendering.c a;

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public e(@NotNull Context context) {
        this(context, null);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    public final com.quizlet.richtext.rendering.c getRichTextRenderer() {
        return this.a;
    }

    public final void h(com.quizlet.richtext.model.a aVar, CharSequence fallbackPlaintext, boolean z) {
        com.quizlet.richtext.rendering.c cVar;
        CharSequence charSequenceA;
        Intrinsics.checkNotNullParameter(fallbackPlaintext, "fallbackPlaintext");
        if (aVar != null && this.a == null) {
            timber.log.c.a.e(new IllegalStateException("Attempting to call setRichTextPayload without setting richTextRenderer"));
        }
        if (z && aVar != null && (cVar = this.a) != null && (charSequenceA = ((com.quizlet.richtext.rendering.a) cVar).a(aVar, fallbackPlaintext)) != null) {
            fallbackPlaintext = charSequenceA;
        }
        super.setText(fallbackPlaintext, TextView.BufferType.NORMAL);
    }

    public final void setRichTextPayload(@NotNull CharSequence fallbackPlaintext) {
        Intrinsics.checkNotNullParameter(fallbackPlaintext, "fallbackPlaintext");
        h(null, fallbackPlaintext, true);
    }

    public final void setRichTextRenderer(com.quizlet.richtext.rendering.c cVar) {
        this.a = cVar;
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public e(Context context, AttributeSet attributeSet) {
        super(context, attributeSet, 0);
        Intrinsics.checkNotNullParameter(context, "context");
    }
}
