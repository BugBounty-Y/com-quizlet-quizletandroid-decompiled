package com.quizlet.data.model;

import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.data.model.t, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C4166t {
    public final C4114c a;
    public final J1 b;
    public final L1 c;

    public C4166t(C4114c c4114c, J1 streakCalendarData, L1 currentStreakData) {
        Intrinsics.checkNotNullParameter(streakCalendarData, "streakCalendarData");
        Intrinsics.checkNotNullParameter(currentStreakData, "currentStreakData");
        this.a = c4114c;
        this.b = streakCalendarData;
        this.c = currentStreakData;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4166t)) {
            return false;
        }
        C4166t c4166t = (C4166t) obj;
        return Intrinsics.b(this.a, c4166t.a) && Intrinsics.b(this.b, c4166t.b) && Intrinsics.b(this.c, c4166t.c);
    }

    public final int hashCode() {
        C4114c c4114c = this.a;
        return this.c.hashCode() + ((this.b.hashCode() + ((c4114c == null ? 0 : c4114c.hashCode()) * 31)) * 31);
    }

    public final String toString() {
        return "AchievementsRecentsItem(latestBadgeData=" + this.a + ", streakCalendarData=" + this.b + ", currentStreakData=" + this.c + ")";
    }
}
