package com.quizlet.data.model;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class S1 {
    public final I a;
    public final User b;

    public S1(I contentStudySetCard, User user) {
        Intrinsics.checkNotNullParameter(contentStudySetCard, "contentStudySetCard");
        Intrinsics.checkNotNullParameter(user, "user");
        this.a = contentStudySetCard;
        this.b = user;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof S1)) {
            return false;
        }
        S1 s1 = (S1) obj;
        return Intrinsics.b(this.a, s1.a) && Intrinsics.b(this.b, s1.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "StudySetCardWithCreator(contentStudySetCard=" + this.a + ", user=" + this.b + ")";
    }
}
