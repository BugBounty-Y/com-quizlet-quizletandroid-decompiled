package com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class d implements h {
    public final LearnSettingsUpdateData a;

    public d(LearnSettingsUpdateData learnSettingsUpdateData) {
        Intrinsics.checkNotNullParameter(learnSettingsUpdateData, "learnSettingsUpdateData");
        this.a = learnSettingsUpdateData;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof d) && Intrinsics.b(this.a, ((d) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "RestartLearnButtonClicked(learnSettingsUpdateData=" + this.a + ")";
    }
}
