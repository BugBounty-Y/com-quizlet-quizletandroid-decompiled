package com.quizlet.features.flashcards;

import android.os.Bundle;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes2.dex */
public final class FlashcardsActivity extends com.quizlet.features.achievements.ui.e {
    public static final String j;
    public final com.quizlet.data.repository.folderwithcreatorinclass.e i;

    static {
        Intrinsics.checkNotNullExpressionValue("FlashcardsActivity", "getSimpleName(...)");
        j = "FlashcardsActivity";
    }

    public FlashcardsActivity() {
        super(2);
        this.i = new com.quizlet.data.repository.folderwithcreatorinclass.e(kotlin.jvm.internal.K.a(S.class), new C4230d(this, 1), new C4230d(this, 0), new C4230d(this, 2));
    }

    @Override // com.quizlet.features.achievements.ui.e, com.quizlet.baseui.base.c, androidx.fragment.app.I, androidx.activity.s, androidx.core.app.AbstractActivityC1021h, android.app.Activity
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        androidx.activity.v.b(this, null, 3);
        androidx.activity.compose.j.a(this, new androidx.compose.runtime.internal.d(true, 1733316981, new C4229c(this, 1)));
    }

    @Override // com.quizlet.baseui.base.c
    public final String y() {
        return j;
    }
}
