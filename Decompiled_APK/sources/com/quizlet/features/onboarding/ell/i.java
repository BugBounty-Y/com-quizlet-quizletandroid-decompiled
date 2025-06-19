package com.quizlet.features.onboarding.ell;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class i implements l {
    public final boolean a;
    public final m b;

    public i(boolean z, m onboardingELLExam) {
        Intrinsics.checkNotNullParameter(onboardingELLExam, "onboardingELLExam");
        this.a = z;
        this.b = onboardingELLExam;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof i)) {
            return false;
        }
        i iVar = (i) obj;
        return this.a == iVar.a && this.b == iVar.b;
    }

    public final int hashCode() {
        return this.b.hashCode() + (Boolean.hashCode(this.a) * 31);
    }

    public final String toString() {
        return "ExamToggleStateChanged(isToggled=" + this.a + ", onboardingELLExam=" + this.b + ")";
    }
}
