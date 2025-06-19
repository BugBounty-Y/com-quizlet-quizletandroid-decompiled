package com.quizlet.features.practicetest.takingtest.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class B implements E {
    public final String a;

    public B(String upgradeSource) {
        com.quizlet.features.infra.models.upgrade.a navigationSource = com.quizlet.features.infra.models.upgrade.a.x;
        Intrinsics.checkNotNullParameter(upgradeSource, "upgradeSource");
        Intrinsics.checkNotNullParameter(navigationSource, "navigationSource");
        this.a = upgradeSource;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof B)) {
            return false;
        }
        if (!this.a.equals(((B) obj).a)) {
            return false;
        }
        retrofit2.adapter.rxjava3.d dVar = com.quizlet.features.infra.models.upgrade.a.b;
        return true;
    }

    public final int hashCode() {
        return com.quizlet.features.infra.models.upgrade.a.x.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "Paywall(upgradeSource=" + this.a + ", navigationSource=" + com.quizlet.features.infra.models.upgrade.a.x + ")";
    }
}
