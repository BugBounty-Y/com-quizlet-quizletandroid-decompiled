package com.quizlet.quizletandroid.ui.studymodes.testmode.start;

import com.quizlet.features.infra.studysetting.data.TestStudyModeConfig;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class g extends h {
    public final TestStudyModeConfig a;

    public g(TestStudyModeConfig testStudyModeConfig) {
        Intrinsics.checkNotNullParameter(testStudyModeConfig, "testStudyModeConfig");
        this.a = testStudyModeConfig;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof g) && Intrinsics.b(this.a, ((g) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "StartTest(testStudyModeConfig=" + this.a + ")";
    }
}
