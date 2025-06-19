package com.quizlet.data.interactor.practicetests;

import com.quizlet.data.model.S0;
import java.util.Comparator;

/* loaded from: classes2.dex */
public final class b implements Comparator {
    public final /* synthetic */ long a;

    public b(long j) {
        this.a = j;
    }

    @Override // java.util.Comparator
    public final int compare(Object obj, Object obj2) {
        long j = ((S0) obj).g;
        long j2 = this.a;
        return kotlin.comparisons.a.b(Long.valueOf(Math.abs(j - j2)), Long.valueOf(Math.abs(((S0) obj2).g - j2)));
    }
}
