package com.quizlet.shared.usecase.studynotes;

import com.quizlet.shared.models.api.notes.NotesTermSetArtifactResponse;

/* loaded from: classes3.dex */
public final class e extends kotlin.coroutines.jvm.internal.c {
    public String j;
    public com.quizlet.shared.enums.studynotes.d k;
    public NotesTermSetArtifactResponse l;
    public /* synthetic */ Object m;
    public final /* synthetic */ f n;
    public int o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public e(f fVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.n = fVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.m = obj;
        this.o |= Integer.MIN_VALUE;
        return this.n.a(null, this);
    }
}
