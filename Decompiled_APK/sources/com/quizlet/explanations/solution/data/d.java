package com.quizlet.explanations.solution.data;

import com.quizlet.data.model.Solution;
import java.util.List;
import kotlin.collections.A;
import kotlin.collections.CollectionsKt;
import kotlin.collections.K;

/* loaded from: classes2.dex */
public abstract class d implements i {
    public final List a;
    public final boolean b;

    public d(List list, boolean z) {
        this.a = list;
        this.b = z;
    }

    @Override // com.quizlet.explanations.solution.data.i
    public final List b() {
        Solution solution;
        List listB;
        List list = this.b ? this.a : null;
        return (list == null || (solution = (Solution) CollectionsKt.firstOrNull(list)) == null || (listB = A.b(new Solution(CollectionsKt.p0(solution.a, 1), solution.b))) == null) ? K.a : listB;
    }

    @Override // com.quizlet.explanations.solution.data.i
    public final boolean c() {
        return true;
    }
}
