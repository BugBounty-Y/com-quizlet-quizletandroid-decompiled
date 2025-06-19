package com.quizlet.features.blocks;

import android.os.Bundle;
import androidx.activity.compose.j;
import androidx.activity.v;
import androidx.lifecycle.p0;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;
import kotlinx.coroutines.E;

@Metadata
/* loaded from: classes2.dex */
public final class GamesActivity extends com.quizlet.features.achievements.ui.e {
    public static final String l;
    public com.quizlet.features.consent.onetrust.d i;
    public final com.quizlet.data.repository.folderwithcreatorinclass.e j;
    public final String k;

    static {
        Intrinsics.checkNotNullExpressionValue("GamesActivity", "getSimpleName(...)");
        l = "GamesActivity";
    }

    public GamesActivity() {
        super(1);
        this.j = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(g.class), new d(this, 1), new d(this, 0), new d(this, 2));
        this.k = l;
    }

    @Override // com.quizlet.features.achievements.ui.e, com.quizlet.baseui.base.c, androidx.fragment.app.I, androidx.activity.s, androidx.core.app.AbstractActivityC1021h, android.app.Activity
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        v.b(this, null, 3);
        j.a(this, new androidx.compose.runtime.internal.d(true, -789460438, new b(this, 1)));
        E.A(p0.h(this), null, null, new c(this, null), 3);
    }

    @Override // com.quizlet.baseui.base.c
    public final String y() {
        return this.k;
    }
}
