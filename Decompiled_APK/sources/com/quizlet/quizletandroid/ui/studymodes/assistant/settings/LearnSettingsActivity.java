package com.quizlet.quizletandroid.ui.studymodes.assistant.settings;

import android.os.Bundle;
import androidx.activity.v;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes3.dex */
public final class LearnSettingsActivity extends com.quizlet.features.achievements.ui.e {
    public static final String i;

    static {
        String name = LearnSettingsActivity.class.getName();
        Intrinsics.checkNotNullExpressionValue(name, "getName(...)");
        i = name;
    }

    public LearnSettingsActivity() {
        super(5);
    }

    @Override // com.quizlet.features.achievements.ui.e, com.quizlet.baseui.base.c, androidx.fragment.app.I, androidx.activity.s, androidx.core.app.AbstractActivityC1021h, android.app.Activity
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        v.b(this, null, 3);
        androidx.activity.compose.j.a(this, new androidx.compose.runtime.internal.d(true, 1115862268, new i(this, 1)));
    }

    @Override // com.quizlet.baseui.base.c
    public final String y() {
        return i;
    }
}
