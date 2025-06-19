package com.quizlet.features.infra.legacyadapter.section;

import com.quizlet.quizletandroid.util.o;

/* loaded from: classes3.dex */
public final class b extends a {
    public final o b;
    public final long c;

    public b(o oVar, long j) {
        this.b = oVar;
        this.c = j;
    }

    @Override // com.quizlet.features.infra.legacyadapter.section.a
    public final int a() {
        return this.a.size() + 1;
    }

    @Override // com.quizlet.features.infra.legacyadapter.section.a
    public final Object b(int i) {
        if (i == 0) {
            return null;
        }
        return super.b(i - 1);
    }
}
