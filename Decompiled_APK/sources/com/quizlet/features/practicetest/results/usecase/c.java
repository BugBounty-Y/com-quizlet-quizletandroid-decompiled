package com.quizlet.features.practicetest.results.usecase;

import com.quizlet.data.model.Y0;
import com.quizlet.data.repository.folderwithcreator.e;
import java.util.ArrayList;

/* loaded from: classes3.dex */
public final class c extends kotlin.coroutines.jvm.internal.c {
    public e j;
    public Y0 k;
    public ArrayList l;
    public ArrayList m;
    public int n;
    public int o;
    public int p;
    public /* synthetic */ Object q;
    public final /* synthetic */ e r;
    public int s;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(e eVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.r = eVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.q = obj;
        this.s |= Integer.MIN_VALUE;
        return this.r.l(null, this);
    }
}
