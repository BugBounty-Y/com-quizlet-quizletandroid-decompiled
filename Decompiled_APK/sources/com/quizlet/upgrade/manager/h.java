package com.quizlet.upgrade.manager;

import com.quizlet.upgrade.data.UpgradePackage;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class h implements i {
    public final UpgradePackage a;

    public h(UpgradePackage upgradePackage) {
        Intrinsics.checkNotNullParameter(upgradePackage, "upgradePackage");
        this.a = upgradePackage;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof h) && Intrinsics.b(this.a, ((h) obj).a);
    }

    public final int hashCode() {
        return this.a.a.hashCode();
    }

    public final String toString() {
        return "Success(upgradePackage=" + this.a + ")";
    }
}
