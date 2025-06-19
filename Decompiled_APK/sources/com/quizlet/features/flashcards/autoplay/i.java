package com.quizlet.features.flashcards.autoplay;

/* loaded from: classes2.dex */
public final class i extends kotlin.coroutines.jvm.internal.c {
    public FlashcardsAutoplayService j;
    public com.quizlet.features.flashcards.data.b k;
    public /* synthetic */ Object l;
    public final /* synthetic */ FlashcardsAutoplayService m;
    public int n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public i(FlashcardsAutoplayService flashcardsAutoplayService, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.m = flashcardsAutoplayService;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.l = obj;
        this.n |= Integer.MIN_VALUE;
        int i = FlashcardsAutoplayService.o;
        return this.m.c(null, false, this);
    }
}
