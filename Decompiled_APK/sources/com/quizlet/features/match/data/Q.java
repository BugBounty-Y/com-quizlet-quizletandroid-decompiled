package com.quizlet.features.match.data;

import com.quizlet.features.match.settings.MatchSettingsData;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class Q {
    public final MatchSettingsData a;
    public final int b;

    public Q(MatchSettingsData matchSettings, int i) {
        Intrinsics.checkNotNullParameter(matchSettings, "matchSettings");
        this.a = matchSettings;
        this.b = i;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof Q)) {
            return false;
        }
        Q q = (Q) obj;
        return Intrinsics.b(this.a, q.a) && this.b == q.b;
    }

    public final int hashCode() {
        return Integer.hashCode(this.b) + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "MatchStartButtonsSettingsData(matchSettings=" + this.a + ", selectedTermsSize=" + this.b + ")";
    }
}
