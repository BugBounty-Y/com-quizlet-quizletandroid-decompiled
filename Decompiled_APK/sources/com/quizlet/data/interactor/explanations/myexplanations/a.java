package com.quizlet.data.interactor.explanations.myexplanations;

import com.quizlet.data.model.B0;
import java.util.Comparator;

/* loaded from: classes2.dex */
public final class a implements Comparator {
    @Override // java.util.Comparator
    public final int compare(Object obj, Object obj2) {
        return kotlin.comparisons.a.b(Long.valueOf(((B0) obj2).a()), Long.valueOf(((B0) obj).a()));
    }
}
