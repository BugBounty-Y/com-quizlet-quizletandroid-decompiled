package com.quizlet.data.interactor.achievements;

import com.quizlet.data.model.C4106a;
import com.quizlet.data.model.C4121d2;
import com.quizlet.data.model.C4155p;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class i {
    public final C4106a a;
    public final C4155p b;
    public final C4121d2 c;

    public i(C4106a c4106a, C4155p c4155p, C4121d2 c4121d2) {
        this.a = c4106a;
        this.b = c4155p;
        this.c = c4121d2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof i)) {
            return false;
        }
        i iVar = (i) obj;
        return Intrinsics.b(this.a, iVar.a) && Intrinsics.b(this.b, iVar.b) && Intrinsics.b(this.c, iVar.c);
    }

    public final int hashCode() {
        C4106a c4106a = this.a;
        int iHashCode = (c4106a == null ? 0 : c4106a.hashCode()) * 31;
        C4155p c4155p = this.b;
        int iHashCode2 = (iHashCode + (c4155p == null ? 0 : c4155p.a.hashCode())) * 31;
        C4121d2 c4121d2 = this.c;
        return iHashCode2 + (c4121d2 != null ? c4121d2.hashCode() : 0);
    }

    public final String toString() {
        return "AchievementsRecentsData(latestBadge=" + this.a + ", achievementsHistory=" + this.b + ", studyStreak=" + this.c + ")";
    }
}
