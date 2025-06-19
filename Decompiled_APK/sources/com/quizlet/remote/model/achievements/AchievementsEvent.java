package com.quizlet.remote.model.achievements;

import androidx.compose.animation.d0;
import com.squareup.moshi.m;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class AchievementsEvent {
    public final String a;
    public final String b;
    public final String c;

    public AchievementsEvent(String target, String action, String str) {
        Intrinsics.checkNotNullParameter(target, "target");
        Intrinsics.checkNotNullParameter(action, "action");
        this.a = target;
        this.b = action;
        this.c = str;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof AchievementsEvent)) {
            return false;
        }
        AchievementsEvent achievementsEvent = (AchievementsEvent) obj;
        return Intrinsics.b(this.a, achievementsEvent.a) && Intrinsics.b(this.b, achievementsEvent.b) && Intrinsics.b(this.c, achievementsEvent.c);
    }

    public final int hashCode() {
        int iE = d0.e(this.a.hashCode() * 31, 31, this.b);
        String str = this.c;
        return iE + (str == null ? 0 : str.hashCode());
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("AchievementsEvent(target=");
        sb.append(this.a);
        sb.append(", action=");
        sb.append(this.b);
        sb.append(", targetId=");
        return android.support.v4.media.session.a.t(sb, this.c, ")");
    }
}
