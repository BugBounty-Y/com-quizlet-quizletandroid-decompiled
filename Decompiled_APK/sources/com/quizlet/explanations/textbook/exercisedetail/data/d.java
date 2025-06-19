package com.quizlet.explanations.textbook.exercisedetail.data;

import com.quizlet.explanations.solution.data.j;
import java.util.List;
import kotlin.collections.K;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class d {
    public final List a;
    public final j b;
    public final K c;
    public final List d;

    public d(List headerList, j solutionViewState, K extraInfoList, List footerList) {
        Intrinsics.checkNotNullParameter(headerList, "headerList");
        Intrinsics.checkNotNullParameter(solutionViewState, "solutionViewState");
        Intrinsics.checkNotNullParameter(extraInfoList, "extraInfoList");
        Intrinsics.checkNotNullParameter(footerList, "footerList");
        this.a = headerList;
        this.b = solutionViewState;
        this.c = extraInfoList;
        this.d = footerList;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof d)) {
            return false;
        }
        d dVar = (d) obj;
        return Intrinsics.b(this.a, dVar.a) && this.b.equals(dVar.b) && Intrinsics.b(this.c, dVar.c) && Intrinsics.b(this.d, dVar.d);
    }

    public final int hashCode() {
        int iHashCode = (this.b.hashCode() + (this.a.hashCode() * 31)) * 31;
        this.c.getClass();
        return this.d.hashCode() + ((1 + iHashCode) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("ExerciseDetailViewState(headerList=");
        sb.append(this.a);
        sb.append(", solutionViewState=");
        sb.append(this.b);
        sb.append(", extraInfoList=");
        sb.append(this.c);
        sb.append(", footerList=");
        return android.support.v4.media.session.a.n(")", sb, this.d);
    }
}
