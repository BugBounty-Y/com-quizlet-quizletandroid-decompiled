package com.quizlet.features.achievements.achievement;

import com.quizlet.data.model.C4114c;
import com.quizlet.generated.enums.EnumC4485h;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class a {
    public final EnumC4485h a;
    public final C4114c b;
    public final g c;

    public a(EnumC4485h type, C4114c achievementBadgeData, g theme) {
        Intrinsics.checkNotNullParameter(type, "type");
        Intrinsics.checkNotNullParameter(achievementBadgeData, "achievementBadgeData");
        Intrinsics.checkNotNullParameter(theme, "theme");
        this.a = type;
        this.b = achievementBadgeData;
        this.c = theme;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        a aVar = (a) obj;
        return this.a == aVar.a && Intrinsics.b(this.b, aVar.b) && this.c == aVar.c;
    }

    public final int hashCode() {
        return this.c.hashCode() + ((this.b.hashCode() + (this.a.hashCode() * 31)) * 31);
    }

    public final String toString() {
        return "AchievementEarnedData(type=" + this.a + ", achievementBadgeData=" + this.b + ", theme=" + this.c + ")";
    }
}
