package com.quizlet.features.achievements.achievement;

import androidx.compose.animation.d0;

/* loaded from: classes2.dex */
public final class l {
    public final int a;
    public final boolean b;
    public final boolean c;

    public l(int i, boolean z, boolean z2) {
        this.a = i;
        this.b = z;
        this.c = z2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof l)) {
            return false;
        }
        l lVar = (l) obj;
        return this.a == lVar.a && this.b == lVar.b && this.c == lVar.c;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.c) + d0.g(Integer.hashCode(this.a) * 31, 31, this.b);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("StreakDay(day=");
        sb.append(this.a);
        sb.append(", isToday=");
        sb.append(this.b);
        sb.append(", hasStreak=");
        return android.support.v4.media.session.a.o(")", sb, this.c);
    }
}
