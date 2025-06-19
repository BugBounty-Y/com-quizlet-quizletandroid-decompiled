package com.quizlet.data.model;

import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.data.model.b2, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C4113b2 {
    public final StudySet a;
    public final User b;
    public final com.quizlet.data.model.search.d c;

    public C4113b2(StudySet studySet, User user, com.quizlet.data.model.search.d dVar) {
        Intrinsics.checkNotNullParameter(studySet, "studySet");
        this.a = studySet;
        this.b = user;
        this.c = dVar;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4113b2)) {
            return false;
        }
        C4113b2 c4113b2 = (C4113b2) obj;
        return Intrinsics.b(this.a, c4113b2.a) && Intrinsics.b(this.b, c4113b2.b) && Intrinsics.b(this.c, c4113b2.c);
    }

    public final int hashCode() {
        int iHashCode = this.a.hashCode() * 31;
        User user = this.b;
        int iHashCode2 = (iHashCode + (user == null ? 0 : user.hashCode())) * 31;
        com.quizlet.data.model.search.d dVar = this.c;
        return iHashCode2 + (dVar != null ? dVar.hashCode() : 0);
    }

    public final String toString() {
        return "StudySetWithCreatorAndSocialSignals(studySet=" + this.a + ", creator=" + this.b + ", socialSignals=" + this.c + ")";
    }
}
