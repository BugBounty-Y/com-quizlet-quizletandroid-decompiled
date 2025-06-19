package com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data;

import androidx.compose.animation.d0;
import java.util.List;
import kotlin.collections.K;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class p implements q {
    public final List a;
    public final a b;
    public final String c;
    public final boolean d;
    public final boolean e;

    public p(List results, a resultType, boolean z, boolean z2) {
        Intrinsics.checkNotNullParameter(results, "results");
        Intrinsics.checkNotNullParameter(resultType, "resultType");
        Intrinsics.checkNotNullParameter("", "selectedSchoolName");
        this.a = results;
        this.b = resultType;
        this.c = "";
        this.d = z;
        this.e = z2;
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
        if (!(obj instanceof p)) {
            return false;
        }
        p pVar = (p) obj;
        return Intrinsics.b(this.a, pVar.a) && this.b == pVar.b && Intrinsics.b(this.c, pVar.c) && this.d == pVar.d && this.e == pVar.e;
    }

    @Override // com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.q
    public final List getResults() {
        return this.a;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.e) + d0.g(d0.e((this.b.hashCode() + (this.a.hashCode() * 31)) * 31, 31, this.c), 31, this.d);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("SearchSchool(results=");
        sb.append(this.a);
        sb.append(", resultType=");
        sb.append(this.b);
        sb.append(", selectedSchoolName=");
        sb.append(this.c);
        sb.append(", isSuggestions=");
        sb.append(this.d);
        sb.append(", requestSchoolFocus=");
        return android.support.v4.media.session.a.o(")", sb, this.e);
    }

    public p(List list, a aVar, boolean z, int i) {
        this((i & 1) != 0 ? K.a : list, aVar, (i & 8) != 0 ? false : z, false);
    }
}
