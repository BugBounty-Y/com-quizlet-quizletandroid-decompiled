package com.braze.requests.framework.queue;

import java.util.Comparator;

/* loaded from: classes.dex */
public final class b implements Comparator {
    @Override // java.util.Comparator
    public final int compare(Object obj, Object obj2) {
        return kotlin.comparisons.a.b(Long.valueOf(((com.braze.requests.framework.h) obj).b), Long.valueOf(((com.braze.requests.framework.h) obj2).b));
    }
}
