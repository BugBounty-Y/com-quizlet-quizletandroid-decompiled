package com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data;

import com.quizlet.learn.settings.data.LearnSettingsResult;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class i implements l {
    public final LearnSettingsResult a;

    public i(LearnSettingsResult learnSettingsResult) {
        Intrinsics.checkNotNullParameter(learnSettingsResult, "learnSettingsResult");
        this.a = learnSettingsResult;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof i) && Intrinsics.b(this.a, ((i) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "Back(learnSettingsResult=" + this.a + ")";
    }
}
