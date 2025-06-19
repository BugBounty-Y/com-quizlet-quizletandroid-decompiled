package com.quizlet.upgrade.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class J {
    public final com.quizlet.upgrade.ui.widgets.b a;
    public final com.quizlet.upgrade.ui.widgets.b b;
    public final com.quizlet.upgrade.ui.widgets.b c;

    public J(com.quizlet.upgrade.ui.widgets.b bVar, com.quizlet.upgrade.ui.widgets.b bVar2, com.quizlet.upgrade.ui.widgets.b bVar3) {
        this.a = bVar;
        this.b = bVar2;
        this.c = bVar3;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof J)) {
            return false;
        }
        J j = (J) obj;
        return Intrinsics.b(this.a, j.a) && Intrinsics.b(this.b, j.b) && Intrinsics.b(this.c, j.c);
    }

    public final int hashCode() {
        com.quizlet.upgrade.ui.widgets.b bVar = this.a;
        int iHashCode = (bVar == null ? 0 : bVar.hashCode()) * 31;
        com.quizlet.upgrade.ui.widgets.b bVar2 = this.b;
        int iHashCode2 = (iHashCode + (bVar2 == null ? 0 : bVar2.hashCode())) * 31;
        com.quizlet.upgrade.ui.widgets.b bVar3 = this.c;
        return iHashCode2 + (bVar3 != null ? bVar3.hashCode() : 0);
    }

    public final String toString() {
        return "UpgradeTimeline(firstTask=" + this.a + ", secondTask=" + this.b + ", thirdTask=" + this.c + ")";
    }
}
