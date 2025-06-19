package com.quizlet.data.model;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@com.squareup.moshi.m(generateAdapter = true)
@Metadata
/* loaded from: classes2.dex */
public final class StudySetWithCreator {
    public final StudySet a;
    public final User b;

    public StudySetWithCreator(StudySet studySet, User user) {
        Intrinsics.checkNotNullParameter(studySet, "studySet");
        this.a = studySet;
        this.b = user;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof StudySetWithCreator)) {
            return false;
        }
        StudySetWithCreator studySetWithCreator = (StudySetWithCreator) obj;
        return Intrinsics.b(this.a, studySetWithCreator.a) && Intrinsics.b(this.b, studySetWithCreator.b);
    }

    public final int hashCode() {
        int iHashCode = this.a.hashCode() * 31;
        User user = this.b;
        return iHashCode + (user == null ? 0 : user.hashCode());
    }

    public final String toString() {
        return "StudySetWithCreator(studySet=" + this.a + ", creator=" + this.b + ")";
    }
}
