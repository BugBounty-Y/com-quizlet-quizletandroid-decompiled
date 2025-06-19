package com.quizlet.data.interactor.achievements;

import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class a {
    public final Object a;
    public final Object b;
    public final Object c;
    public final Object d;
    public final Object e;
    public final Object f;
    public final List g;

    public a(List studyData, List dailyStreakData, List weeklyStreakData, List setsStudiedData, List roundsStudiedData, List explanationsStudiedData, List studyGuidesCreated) {
        Intrinsics.checkNotNullParameter(studyData, "studyData");
        Intrinsics.checkNotNullParameter(dailyStreakData, "dailyStreakData");
        Intrinsics.checkNotNullParameter(weeklyStreakData, "weeklyStreakData");
        Intrinsics.checkNotNullParameter(setsStudiedData, "setsStudiedData");
        Intrinsics.checkNotNullParameter(roundsStudiedData, "roundsStudiedData");
        Intrinsics.checkNotNullParameter(explanationsStudiedData, "explanationsStudiedData");
        Intrinsics.checkNotNullParameter(studyGuidesCreated, "studyGuidesCreated");
        this.a = studyData;
        this.b = dailyStreakData;
        this.c = weeklyStreakData;
        this.d = setsStudiedData;
        this.e = roundsStudiedData;
        this.f = explanationsStudiedData;
        this.g = studyGuidesCreated;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        a aVar = (a) obj;
        return Intrinsics.b(this.a, aVar.a) && Intrinsics.b(this.b, aVar.b) && Intrinsics.b(this.c, aVar.c) && Intrinsics.b(this.d, aVar.d) && Intrinsics.b(this.e, aVar.e) && Intrinsics.b(this.f, aVar.f) && Intrinsics.b(this.g, aVar.g);
    }

    public final int hashCode() {
        return this.g.hashCode() + ((this.f.hashCode() + ((this.e.hashCode() + ((this.d.hashCode() + ((this.c.hashCode() + ((this.b.hashCode() + (this.a.hashCode() * 31)) * 31)) * 31)) * 31)) * 31)) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("AchievementBadgesData(studyData=");
        sb.append(this.a);
        sb.append(", dailyStreakData=");
        sb.append(this.b);
        sb.append(", weeklyStreakData=");
        sb.append(this.c);
        sb.append(", setsStudiedData=");
        sb.append(this.d);
        sb.append(", roundsStudiedData=");
        sb.append(this.e);
        sb.append(", explanationsStudiedData=");
        sb.append(this.f);
        sb.append(", studyGuidesCreated=");
        return android.support.v4.media.session.a.n(")", sb, this.g);
    }
}
