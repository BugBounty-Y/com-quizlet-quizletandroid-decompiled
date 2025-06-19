package com.quizlet.learn.data.onboarding;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class n {
    public final kotlinx.collections.immutable.e a;
    public final k b;

    public n(kotlinx.collections.immutable.e goalItems, k defaultGoal) {
        Intrinsics.checkNotNullParameter(goalItems, "goalItems");
        Intrinsics.checkNotNullParameter(defaultGoal, "defaultGoal");
        this.a = goalItems;
        this.b = defaultGoal;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof n)) {
            return false;
        }
        n nVar = (n) obj;
        return Intrinsics.b(this.a, nVar.a) && Intrinsics.b(this.b, nVar.b);
    }

    public final int hashCode() {
        int iHashCode = this.a.hashCode() * 31;
        this.b.getClass();
        return 270063560 + iHashCode;
    }

    public final String toString() {
        return "OnboardingGoalState(goalItems=" + this.a + ", defaultGoal=" + this.b + ")";
    }
}
