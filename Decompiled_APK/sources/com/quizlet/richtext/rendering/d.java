package com.quizlet.richtext.rendering;

import android.text.SpannedString;
import com.quizlet.quizletandroid.ui.setcreation.managers.n;
import java.util.List;
import kotlin.collections.A;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class d {
    public static final List b = A.b(new SpannedString("\n"));
    public final n a;

    public d(n highlightColorResolver) {
        Intrinsics.checkNotNullParameter(highlightColorResolver, "highlightColorResolver");
        this.a = highlightColorResolver;
    }
}
