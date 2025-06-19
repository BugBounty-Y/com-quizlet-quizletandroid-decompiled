package com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data;

import androidx.compose.animation.d0;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class o implements q {
    public final List a;
    public final a b;
    public final String c;
    public final boolean d;

    public o(List results, a resultType, String selectedSchoolName, boolean z) {
        Intrinsics.checkNotNullParameter(results, "results");
        Intrinsics.checkNotNullParameter(resultType, "resultType");
        Intrinsics.checkNotNullParameter(selectedSchoolName, "selectedSchoolName");
        this.a = results;
        this.b = resultType;
        this.c = selectedSchoolName;
        this.d = z;
    }

    @Override // com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.q
    public final String a() {
        return this.c;
    }

    @Override // com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.q
    public final a b() {
        return this.b;
    }

    @Override // com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.q
    public final boolean c() {
        return this.d;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof o)) {
            return false;
        }
        o oVar = (o) obj;
        return Intrinsics.b(this.a, oVar.a) && this.b == oVar.b && Intrinsics.b(this.c, oVar.c) && this.d == oVar.d;
    }

    @Override // com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.q
    public final List getResults() {
        return this.a;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.d) + d0.e((this.b.hashCode() + (this.a.hashCode() * 31)) * 31, 31, this.c);
    }

    public final String toString() {
        return "SearchCourse(results=" + this.a + ", resultType=" + this.b + ", selectedSchoolName=" + this.c + ", isSuggestions=" + this.d + ")";
    }
}
