package com.quizlet.features.practicetest.takingtest.data;

import com.quizlet.features.practicetest.common.data.PracticeTestConfigurationData;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class M {
    public final String a;
    public final kotlinx.collections.immutable.g b;
    public final PracticeTestConfigurationData c;

    public M(String testTitle, kotlinx.collections.immutable.g questionCounts, PracticeTestConfigurationData configData) {
        Intrinsics.checkNotNullParameter(testTitle, "testTitle");
        Intrinsics.checkNotNullParameter(questionCounts, "questionCounts");
        Intrinsics.checkNotNullParameter(configData, "configData");
        this.a = testTitle;
        this.b = questionCounts;
        this.c = configData;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof M)) {
            return false;
        }
        M m = (M) obj;
        return Intrinsics.b(this.a, m.a) && Intrinsics.b(this.b, m.b) && Intrinsics.b(this.c, m.c);
    }

    public final int hashCode() {
        return this.c.hashCode() + ((this.b.hashCode() + (this.a.hashCode() * 31)) * 31);
    }

    public final String toString() {
        return "SettingsData(testTitle=" + this.a + ", questionCounts=" + this.b + ", configData=" + this.c + ")";
    }
}
