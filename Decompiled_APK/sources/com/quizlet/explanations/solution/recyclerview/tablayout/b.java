package com.quizlet.explanations.solution.recyclerview.tablayout;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class b implements com.quizlet.baserecyclerview.a {
    public final int a;
    public final com.quizlet.explanations.solution.fragments.b b;
    public int c;

    public b(int i, com.quizlet.explanations.solution.fragments.b onTabSelected) {
        Intrinsics.checkNotNullParameter(onTabSelected, "onTabSelected");
        this.a = i;
        this.b = onTabSelected;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof b)) {
            return false;
        }
        b bVar = (b) obj;
        return this.a == bVar.a && this.b.equals(bVar.b);
    }

    @Override // com.quizlet.baserecyclerview.a
    public final /* bridge */ /* synthetic */ Object getItemId() {
        return "solutionTabLayoutId";
    }

    public final int hashCode() {
        return this.b.hashCode() + (Integer.hashCode(this.a) * 31);
    }

    public final String toString() {
        return "SolutionTabLayoutItem(tabCount=" + this.a + ", onTabSelected=" + this.b + ")";
    }
}
