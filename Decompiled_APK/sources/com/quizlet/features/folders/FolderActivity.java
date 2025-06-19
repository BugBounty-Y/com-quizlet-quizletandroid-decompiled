package com.quizlet.features.folders;

import android.os.Bundle;
import androidx.activity.compose.j;
import androidx.activity.v;
import androidx.compose.runtime.internal.d;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes3.dex */
public final class FolderActivity extends c {
    public static final String j;
    public com.quizlet.quizletandroid.managers.c i;

    static {
        Intrinsics.checkNotNullExpressionValue("FolderActivity", "getSimpleName(...)");
        j = "FolderActivity";
    }

    public FolderActivity() {
        super(0);
    }

    @Override // com.quizlet.features.folders.c, com.quizlet.baseui.base.c, androidx.fragment.app.I, androidx.activity.s, androidx.core.app.AbstractActivityC1021h, android.app.Activity
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        v.b(this, null, 3);
        j.a(this, new d(true, 436156409, new a(this, 1)));
    }

    @Override // com.quizlet.baseui.base.c, androidx.fragment.app.I, android.app.Activity
    public final void onResume() {
        super.onResume();
        com.quizlet.quizletandroid.managers.c cVar = this.i;
        if (cVar == null) {
            Intrinsics.m("conversionTrackingManager");
            throw null;
        }
        cVar.a.a(new com.quizlet.quizletandroid.managers.a(this, getIntent().getData()));
    }

    @Override // com.quizlet.baseui.base.c
    public final String y() {
        return j;
    }
}
