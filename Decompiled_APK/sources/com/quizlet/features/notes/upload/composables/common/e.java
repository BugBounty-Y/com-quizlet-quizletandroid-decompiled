package com.quizlet.features.notes.upload.composables.common;

import android.view.KeyEvent;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class e implements Function1 {
    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        KeyEvent it2 = ((androidx.compose.ui.input.key.b) obj).a;
        Intrinsics.checkNotNullParameter(it2, "it");
        if (androidx.compose.ui.input.key.a.a(androidx.compose.ui.input.key.c.b(it2), androidx.compose.ui.input.key.a.k)) {
            androidx.compose.ui.input.key.c.c(it2);
        }
        return Boolean.FALSE;
    }
}
