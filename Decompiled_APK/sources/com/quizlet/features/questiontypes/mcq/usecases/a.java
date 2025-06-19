package com.quizlet.features.questiontypes.mcq.usecases;

import com.quizlet.data.repository.studysetwithcreator.d;
import kotlin.coroutines.jvm.internal.c;

/* loaded from: classes3.dex */
public final class a extends c {
    public d j;
    public int k;
    public boolean l;
    public boolean m;
    public /* synthetic */ Object n;
    public final /* synthetic */ d o;
    public int p;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(d dVar, c cVar) {
        super(cVar);
        this.o = dVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.n = obj;
        this.p |= Integer.MIN_VALUE;
        return this.o.b(null, 0, false, false, this);
    }
}
