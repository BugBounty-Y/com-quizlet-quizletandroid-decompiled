package com.quizlet.features.setpage;

import android.os.Bundle;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes3.dex */
public final class NewSetPageActivity extends com.quizlet.features.folders.c {
    public static final String j;
    public final String i;

    static {
        Intrinsics.checkNotNullExpressionValue("NewSetPageActivity", "getSimpleName(...)");
        j = "NewSetPageActivity";
    }

    public NewSetPageActivity() {
        super(1);
        this.i = j;
    }

    @Override // com.quizlet.features.folders.c, com.quizlet.baseui.base.c, androidx.fragment.app.I, androidx.activity.s, androidx.core.app.AbstractActivityC1021h, android.app.Activity
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        androidx.activity.compose.j.a(this, b.b);
    }

    @Override // com.quizlet.baseui.base.c
    public final String y() {
        return this.i;
    }
}
