package com.quizlet.features.setpage.screenstates;

import com.quizlet.db.data.models.persisted.DBStudySet;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.features.setpage.screenstates.f, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4426f extends h {
    public final DBStudySet a;
    public final com.quizlet.features.infra.basestudy.data.models.shareset.a b;

    public C4426f(DBStudySet set, com.quizlet.features.infra.basestudy.data.models.shareset.a shareStatus) {
        Intrinsics.checkNotNullParameter(set, "set");
        Intrinsics.checkNotNullParameter(shareStatus, "shareStatus");
        this.a = set;
        this.b = shareStatus;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4426f)) {
            return false;
        }
        C4426f c4426f = (C4426f) obj;
        return Intrinsics.b(this.a, c4426f.a) && this.b == c4426f.b;
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "ShowShareSet(set=" + this.a + ", shareStatus=" + this.b + ")";
    }
}
