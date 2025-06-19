package com.quizlet.features.match.data;

import com.quizlet.utm.a;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class H {
    public final com.quizlet.features.infra.basestudy.data.models.shareset.a a;
    public final long b;
    public final String c;
    public final String d;
    public final a.C0023a e;
    public final com.quizlet.qutils.string.f f;

    public H(com.quizlet.features.infra.basestudy.data.models.shareset.a shareStatus, long j, String str, String setTitle, a.C0023a utmInfo, com.quizlet.qutils.string.f msgStringResData) {
        Intrinsics.checkNotNullParameter(shareStatus, "shareStatus");
        Intrinsics.checkNotNullParameter(setTitle, "setTitle");
        Intrinsics.checkNotNullParameter(utmInfo, "utmInfo");
        Intrinsics.checkNotNullParameter("match", "studyModeUrlFragment");
        Intrinsics.checkNotNullParameter(msgStringResData, "msgStringResData");
        this.a = shareStatus;
        this.b = j;
        this.c = str;
        this.d = setTitle;
        this.e = utmInfo;
        this.f = msgStringResData;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof H)) {
            return false;
        }
        H h = (H) obj;
        return this.a == h.a && this.b == h.b && this.c.equals(h.c) && this.d.equals(h.d) && this.e.equals(h.e) && this.f.equals(h.f);
    }

    public final int hashCode() {
        return this.f.hashCode() + ((((this.e.hashCode() + androidx.compose.animation.d0.e(androidx.compose.animation.d0.e(androidx.compose.animation.d0.d(this.a.hashCode() * 31, 31, this.b), 31, this.c), 31, this.d)) * 31) + 103668165) * 31);
    }

    public final String toString() {
        return "MatchInfoForSharing(shareStatus=" + this.a + ", studiableModelId=" + this.b + ", webUrl=" + this.c + ", setTitle=" + this.d + ", utmInfo=" + this.e + ", studyModeUrlFragment=match, msgStringResData=" + this.f + ")";
    }
}
