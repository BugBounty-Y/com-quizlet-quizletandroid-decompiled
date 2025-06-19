package com.quizlet.features.flashcards.autoplay;

/* loaded from: classes2.dex */
public final class j extends kotlin.coroutines.jvm.internal.c {
    public FlashcardsAutoplayService j;
    public /* synthetic */ Object k;
    public final /* synthetic */ FlashcardsAutoplayService l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public j(FlashcardsAutoplayService flashcardsAutoplayService, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.l = flashcardsAutoplayService;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.k = obj;
        this.m |= Integer.MIN_VALUE;
        return FlashcardsAutoplayService.a(this.l, null, this);
    }
}
