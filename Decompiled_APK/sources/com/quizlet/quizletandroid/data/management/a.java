package com.quizlet.quizletandroid.data.management;

import com.quizlet.db.data.models.persisted.DBStudySet;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a {
    public final DBStudySet a;
    public final com.quizlet.qutils.data.offline.d b;
    public final long c;

    public a(DBStudySet studySet, com.quizlet.qutils.data.offline.d payload, long j) {
        Intrinsics.checkNotNullParameter(studySet, "studySet");
        Intrinsics.checkNotNullParameter(payload, "payload");
        this.a = studySet;
        this.b = payload;
        this.c = j;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        a aVar = (a) obj;
        return Intrinsics.b(this.a, aVar.a) && Intrinsics.b(this.b, aVar.b) && this.c == aVar.c;
    }

    public final int hashCode() {
        return Long.hashCode(this.c) + ((this.b.hashCode() + (this.a.hashCode() * 31)) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("ManagerInfo(studySet=");
        sb.append(this.a);
        sb.append(", payload=");
        sb.append(this.b);
        sb.append(", userId=");
        return android.support.v4.media.session.a.g(this.c, ")", sb);
    }
}
