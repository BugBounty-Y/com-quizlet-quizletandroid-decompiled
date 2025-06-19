package com.quizlet.features.achievements.ui;

import android.os.Bundle;
import androidx.activity.compose.j;
import androidx.activity.v;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes2.dex */
public final class AchievementsActivity extends e {
    public static final String i;

    static {
        String name = AchievementsActivity.class.getName();
        Intrinsics.checkNotNullExpressionValue(name, "getName(...)");
        i = name;
    }

    public AchievementsActivity() {
        super(0);
    }

    @Override // com.quizlet.features.achievements.ui.e, com.quizlet.baseui.base.c, androidx.fragment.app.I, androidx.activity.s, androidx.core.app.AbstractActivityC1021h, android.app.Activity
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        v.b(this, null, 3);
        j.a(this, new androidx.compose.runtime.internal.d(true, 928856960, new a(this, 1)));
    }

    @Override // com.quizlet.baseui.base.c
    public final String y() {
        return i;
    }
}
