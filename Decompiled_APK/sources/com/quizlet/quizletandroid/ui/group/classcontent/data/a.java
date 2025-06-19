package com.quizlet.quizletandroid.ui.group.classcontent.data;

import java.util.Comparator;

/* loaded from: classes3.dex */
public final class a implements Comparator {
    @Override // java.util.Comparator
    public final int compare(Object obj, Object obj2) {
        return kotlin.comparisons.a.b(Long.valueOf(((com.quizlet.quizletandroid.ui.group.classcontent.models.a) obj2).a()), Long.valueOf(((com.quizlet.quizletandroid.ui.group.classcontent.models.a) obj).a()));
    }
}
