package com.quizlet.upgrade.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class H {
    public final com.quizlet.upgrade.ui.widgets.a a;
    public final com.quizlet.upgrade.ui.widgets.a b;

    public H(com.quizlet.upgrade.ui.widgets.a aVar, com.quizlet.upgrade.ui.widgets.a aVar2) {
        this.a = aVar;
        this.b = aVar2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof H)) {
            return false;
        }
        H h = (H) obj;
        return Intrinsics.b(this.a, h.a) && Intrinsics.b(this.b, h.b);
    }

    public final int hashCode() {
        com.quizlet.upgrade.ui.widgets.a aVar = this.a;
        int iHashCode = (aVar == null ? 0 : aVar.hashCode()) * 31;
        com.quizlet.upgrade.ui.widgets.a aVar2 = this.b;
        return iHashCode + (aVar2 != null ? aVar2.hashCode() : 0);
    }

    public final String toString() {
        return "UpgradePlanChoiceButtonState(annual=" + this.a + ", monthly=" + this.b + ")";
    }
}
