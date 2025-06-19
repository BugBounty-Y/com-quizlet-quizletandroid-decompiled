package com.quizlet.quizletandroid.ui.studymodes.assistant.settings.navigation;

import java.util.List;
import kotlin.collections.K;

/* loaded from: classes3.dex */
public final class e implements com.quizlet.ui.compose.navigation.b {
    public static final e a = new e();

    @Override // com.quizlet.ui.compose.navigation.b
    public final List a() {
        return K.a;
    }

    @Override // com.quizlet.ui.compose.navigation.b
    public final K c() {
        return K.a;
    }

    @Override // com.quizlet.ui.compose.navigation.b
    public final String e() {
        return "learn_settings_grading";
    }

    public final boolean equals(Object obj) {
        return this == obj || (obj instanceof e);
    }

    public final int hashCode() {
        return 713808337;
    }

    public final String toString() {
        return "LearnSettingsGrading";
    }
}
