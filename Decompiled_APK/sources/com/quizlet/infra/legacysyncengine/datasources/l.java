package com.quizlet.infra.legacysyncengine.datasources;

import com.quizlet.db.data.models.persisted.DBFolder;
import java.util.Comparator;

/* loaded from: classes3.dex */
public final class l implements Comparator {
    @Override // java.util.Comparator
    public final int compare(Object obj, Object obj2) {
        return kotlin.comparisons.a.b(Long.valueOf(((DBFolder) obj2).getLastModified()), Long.valueOf(((DBFolder) obj).getLastModified()));
    }
}
