package com.quizlet.quizletandroid.ui.subject;

import android.os.Bundle;
import androidx.activity.compose.j;
import androidx.activity.v;
import com.quizlet.quizletandroid.ui.common.ads.G;
import com.quizlet.quizletandroid.ui.subject.viewmodel.m;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;

@Metadata
/* loaded from: classes3.dex */
public final class SubjectCategoryActivity extends com.quizlet.features.achievements.ui.e {
    public static final String k;
    public final String i;
    public final com.quizlet.data.repository.folderwithcreatorinclass.e j;

    static {
        Intrinsics.checkNotNullExpressionValue("SubjectCategoryActivity", "getSimpleName(...)");
        k = "SubjectCategoryActivity";
    }

    public SubjectCategoryActivity() {
        super(6);
        this.i = k;
        this.j = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(m.class), new d(this, 1), new d(this, 0), new d(this, 2));
    }

    public final m E() {
        return (m) this.j.getValue();
    }

    @Override // com.quizlet.features.achievements.ui.e, com.quizlet.baseui.base.c, androidx.fragment.app.I, androidx.activity.s, androidx.core.app.AbstractActivityC1021h, android.app.Activity
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        E().g.f(this, new com.quizlet.ads.ui.fragments.c(new G(this, 26), (byte) 0, (byte) 0));
        v.b(this, null, 3);
        j.a(this, new androidx.compose.runtime.internal.d(true, 206330318, new com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.c(this, 3)));
    }

    @Override // com.quizlet.baseui.base.c
    public final String y() {
        return this.i;
    }
}
