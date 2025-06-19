package com.quizlet.richtext.ui;

import android.content.Context;
import android.util.AttributeSet;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.wordpress.aztec.AztecText;

@Metadata
/* loaded from: classes3.dex */
public final class QRichEditText extends AztecText {
    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public QRichEditText(@NotNull Context context, @NotNull AttributeSet attrs) {
        super(context, attrs);
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(attrs, "attrs");
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(attrs, "attrs");
        setInCalypsoMode(false);
    }
}
