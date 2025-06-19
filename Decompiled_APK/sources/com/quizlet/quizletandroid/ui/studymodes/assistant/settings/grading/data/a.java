package com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a implements c {
    public final LearnSettingsGradingUpdateData a;

    public a(LearnSettingsGradingUpdateData learnSettingsGradingUpdateData) {
        Intrinsics.checkNotNullParameter(learnSettingsGradingUpdateData, "learnSettingsGradingUpdateData");
        this.a = learnSettingsGradingUpdateData;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof a) && Intrinsics.b(this.a, ((a) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "BackButtonClicked(learnSettingsGradingUpdateData=" + this.a + ")";
    }
}
