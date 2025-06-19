package com.quizlet.features.onboarding.survey;

import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class n {
    public final List a;
    public final m b;

    public n(List sources, m selectedSource) {
        Intrinsics.checkNotNullParameter(sources, "sources");
        Intrinsics.checkNotNullParameter(selectedSource, "selectedSource");
        this.a = sources;
        this.b = selectedSource;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof n)) {
            return false;
        }
        n nVar = (n) obj;
        return Intrinsics.b(this.a, nVar.a) && this.b == nVar.b;
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "OnboardingSurveyState(sources=" + this.a + ", selectedSource=" + this.b + ")";
    }
}
