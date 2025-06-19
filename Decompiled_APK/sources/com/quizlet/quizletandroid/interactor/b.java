package com.quizlet.quizletandroid.interactor;

import com.quizlet.data.model.S1;
import com.quizlet.db.data.models.persisted.DBGroup;
import com.quizlet.db.data.models.persisted.DBSession;
import java.util.Comparator;

/* loaded from: classes3.dex */
public final class b implements Comparator {
    public final /* synthetic */ int a;

    public /* synthetic */ b(int i) {
        this.a = i;
    }

    @Override // java.util.Comparator
    public final int compare(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                return kotlin.comparisons.a.b(Integer.valueOf(((DBGroup) obj2).getCreatedDate()), Integer.valueOf(((DBGroup) obj).getCreatedDate()));
            case 1:
                return kotlin.comparisons.a.b(Integer.valueOf(((DBGroup) obj2).getCreatedDate()), Integer.valueOf(((DBGroup) obj).getCreatedDate()));
            case 2:
                return kotlin.comparisons.a.b(Long.valueOf(((DBSession) obj2).getLastModified()), Long.valueOf(((DBSession) obj).getLastModified()));
            case 3:
                return kotlin.comparisons.a.b(Boolean.valueOf(!((S1) obj).a.g), Boolean.valueOf(!((S1) obj2).a.g));
            default:
                return kotlin.comparisons.a.b(Long.valueOf(((S1) obj2).a.h), Long.valueOf(((S1) obj).a.h));
        }
    }
}
