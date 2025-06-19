package com.quizlet.features.folders.data;

import kotlin.collections.CollectionsKt;

/* loaded from: classes3.dex */
public final class V0 implements W0 {
    public static final V0 a = new V0();

    @Override // com.quizlet.features.folders.data.W0
    public final kotlinx.collections.immutable.b a() {
        return kotlinx.collections.immutable.implementations.immutableList.g.c;
    }

    @Override // com.quizlet.features.folders.data.W0
    public final boolean b() {
        return false;
    }

    @Override // com.quizlet.features.folders.data.W0
    public final int c() {
        return 0;
    }

    @Override // com.quizlet.features.folders.data.W0
    public final String d() {
        String str;
        com.quizlet.features.infra.models.folders.c cVar = (com.quizlet.features.infra.models.folders.c) CollectionsKt.O(0, a());
        return (cVar == null || (str = cVar.c) == null) ? "" : str;
    }

    @Override // com.quizlet.features.folders.data.W0
    public final boolean e() {
        return false;
    }

    public final boolean equals(Object obj) {
        return this == obj || (obj instanceof V0);
    }

    public final int hashCode() {
        return -1161969451;
    }

    public final String toString() {
        return "Idle";
    }
}
