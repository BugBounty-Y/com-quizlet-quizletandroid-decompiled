package com.quizlet.features.match.data;

import com.quizlet.db.data.models.persisted.DBStudySet;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class W {
    public final com.quizlet.features.infra.basestudy.data.models.shareset.a a;
    public final DBStudySet b;
    public final long c;

    public W(com.quizlet.features.infra.basestudy.data.models.shareset.a shareStatus, DBStudySet dBStudySet, long j) {
        Intrinsics.checkNotNullParameter(shareStatus, "shareStatus");
        Intrinsics.checkNotNullParameter("match", "studyModeUrlFragment");
        this.a = shareStatus;
        this.b = dBStudySet;
        this.c = j;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof W)) {
            return false;
        }
        W w = (W) obj;
        return this.a == w.a && Intrinsics.b(this.b, w.b) && this.c == w.c;
    }

    public final int hashCode() {
        int iHashCode = this.a.hashCode() * 31;
        DBStudySet dBStudySet = this.b;
        return ((Long.hashCode(this.c) + ((iHashCode + (dBStudySet == null ? 0 : dBStudySet.hashCode())) * 31)) * 31) + 103668165;
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("ShareSetData(shareStatus=");
        sb.append(this.a);
        sb.append(", set=");
        sb.append(this.b);
        sb.append(", loggedInUserId=");
        return android.support.v4.media.session.a.g(this.c, ", studyModeUrlFragment=match)", sb);
    }
}
