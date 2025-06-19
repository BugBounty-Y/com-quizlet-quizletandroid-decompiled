package com.quizlet.data.interactor.achievements;

import com.quizlet.data.model.AbstractC4128g;
import com.quizlet.data.model.AbstractC4163s;
import com.quizlet.data.model.C4122e;
import com.quizlet.data.model.C4125f;
import com.quizlet.data.model.C4158q;
import com.quizlet.data.model.f2;
import com.quizlet.data.model.g2;
import com.quizlet.data.model.h2;
import com.quizlet.data.model.r;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class g {
    public final AbstractC4128g a;
    public final h2 b;
    public final AbstractC4163s c;
    public final boolean d;
    public final boolean e;

    public g(AbstractC4128g latestBadge, h2 studyStreak, AbstractC4163s history) {
        Intrinsics.checkNotNullParameter(latestBadge, "latestBadge");
        Intrinsics.checkNotNullParameter(studyStreak, "studyStreak");
        Intrinsics.checkNotNullParameter(history, "history");
        this.a = latestBadge;
        this.b = studyStreak;
        this.c = history;
        boolean z = true;
        this.d = (latestBadge instanceof C4122e) || (studyStreak instanceof f2) || (history instanceof C4158q);
        if ((latestBadge instanceof C4122e) && (studyStreak instanceof f2)) {
            boolean z2 = history instanceof C4158q;
        }
        if (!(latestBadge instanceof C4125f) && !(studyStreak instanceof g2) && !(history instanceof r)) {
            z = false;
        }
        this.e = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof g)) {
            return false;
        }
        g gVar = (g) obj;
        return Intrinsics.b(this.a, gVar.a) && Intrinsics.b(this.b, gVar.b) && Intrinsics.b(this.c, gVar.c);
    }

    public final int hashCode() {
        return this.c.hashCode() + ((this.b.hashCode() + (this.a.hashCode() * 31)) * 31);
    }

    public final String toString() {
        return "AchievementsData(latestBadge=" + this.a + ", studyStreak=" + this.b + ", history=" + this.c + ")";
    }
}
