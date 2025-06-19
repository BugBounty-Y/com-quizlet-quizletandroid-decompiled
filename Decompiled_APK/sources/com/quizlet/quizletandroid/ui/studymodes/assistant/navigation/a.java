package com.quizlet.quizletandroid.ui.studymodes.assistant.navigation;

import com.quizlet.features.infra.models.studymodeshared.StudyableModelData;
import kotlin.coroutines.jvm.internal.c;

/* loaded from: classes3.dex */
public final class a extends c {
    public b j;
    public StudyableModelData k;
    public String l;
    public long m;
    public /* synthetic */ Object n;
    public final /* synthetic */ b o;
    public int p;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(b bVar, c cVar) {
        super(cVar);
        this.o = bVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.n = obj;
        this.p |= Integer.MIN_VALUE;
        return this.o.a(null, null, 0L, this);
    }
}
