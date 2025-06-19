package com.quizlet.features.subjects.model;

import com.quizlet.generated.enums.I1;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b {
    public final I1 a;
    public final List b;

    public b(I1 type, List subjects) {
        Intrinsics.checkNotNullParameter(type, "type");
        Intrinsics.checkNotNullParameter(subjects, "subjects");
        this.a = type;
        this.b = subjects;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof b)) {
            return false;
        }
        b bVar = (b) obj;
        return this.a == bVar.a && Intrinsics.b(this.b, bVar.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "SubjectCategory(type=" + this.a + ", subjects=" + this.b + ")";
    }
}
