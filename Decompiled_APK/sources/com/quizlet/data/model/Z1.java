package com.quizlet.data.model;

import com.google.android.gms.internal.mlkit_vision_document_scanner.J6;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class Z1 {
    public final StudySet a;
    public final User b;
    public final J6 c;

    public Z1(StudySet studySet, User user, J6 classification) {
        Intrinsics.checkNotNullParameter(studySet, "studySet");
        Intrinsics.checkNotNullParameter(classification, "classification");
        this.a = studySet;
        this.b = user;
        this.c = classification;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof Z1)) {
            return false;
        }
        Z1 z1 = (Z1) obj;
        return Intrinsics.b(this.a, z1.a) && Intrinsics.b(this.b, z1.b) && Intrinsics.b(this.c, z1.c);
    }

    public final int hashCode() {
        int iHashCode = this.a.hashCode() * 31;
        User user = this.b;
        return this.c.hashCode() + ((iHashCode + (user == null ? 0 : user.hashCode())) * 31);
    }

    public final String toString() {
        return "StudySetWithCreatorAndClassification(studySet=" + this.a + ", creator=" + this.b + ", classification=" + this.c + ")";
    }
}
