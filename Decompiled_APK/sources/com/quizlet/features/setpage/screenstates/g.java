package com.quizlet.features.setpage.screenstates;

import com.quizlet.db.data.models.persisted.DBStudySet;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class g extends h {
    public final DBStudySet a;
    public final com.quizlet.features.infra.basestudy.data.models.shareset.a b;

    public g(DBStudySet set, com.quizlet.features.infra.basestudy.data.models.shareset.a shareStatus) {
        Intrinsics.checkNotNullParameter(set, "set");
        Intrinsics.checkNotNullParameter(shareStatus, "shareStatus");
        this.a = set;
        this.b = shareStatus;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof g)) {
            return false;
        }
        g gVar = (g) obj;
        return Intrinsics.b(this.a, gVar.a) && this.b == gVar.b;
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "ShowWhatsAppShareSet(set=" + this.a + ", shareStatus=" + this.b + ")";
    }
}
