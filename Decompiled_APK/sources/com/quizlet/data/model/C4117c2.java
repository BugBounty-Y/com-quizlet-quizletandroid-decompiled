package com.quizlet.data.model;

import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.data.model.c2, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C4117c2 {
    public final StudySet a;
    public final User b;
    public final long c;
    public final boolean d;
    public final Long e;

    public C4117c2(StudySet studySet, User user, long j, boolean z, Long l) {
        Intrinsics.checkNotNullParameter(studySet, "studySet");
        this.a = studySet;
        this.b = user;
        this.c = j;
        this.d = z;
        this.e = l;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4117c2)) {
            return false;
        }
        C4117c2 c4117c2 = (C4117c2) obj;
        return Intrinsics.b(this.a, c4117c2.a) && Intrinsics.b(this.b, c4117c2.b) && this.c == c4117c2.c && this.d == c4117c2.d && Intrinsics.b(this.e, c4117c2.e);
    }

    public final int hashCode() {
        int iHashCode = this.a.hashCode() * 31;
        User user = this.b;
        int iG = androidx.compose.animation.d0.g(androidx.compose.animation.d0.d((iHashCode + (user == null ? 0 : user.hashCode())) * 31, 31, this.c), 31, this.d);
        Long l = this.e;
        return iG + (l != null ? l.hashCode() : 0);
    }

    public final String toString() {
        return "StudySetWithCreatorInClass(studySet=" + this.a + ", creator=" + this.b + ", timestampAddedSec=" + this.c + ", canEdit=" + this.d + ", classId=" + this.e + ")";
    }
}
