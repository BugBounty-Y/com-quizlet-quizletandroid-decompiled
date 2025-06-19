package com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.viewmodel;

import com.quizlet.features.infra.studysetting.data.QuestionSettings;

/* loaded from: classes3.dex */
public final class f extends kotlin.coroutines.jvm.internal.c {
    public g j;
    public QuestionSettings k;
    public boolean l;
    public /* synthetic */ Object m;
    public final /* synthetic */ g n;
    public int o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public f(g gVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.n = gVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.m = obj;
        this.o |= Integer.MIN_VALUE;
        return g.A(this.n, null, this);
    }
}
