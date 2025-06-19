package com.quizlet.features.flashcards.autoplay;

/* loaded from: classes2.dex */
public final class h extends kotlin.coroutines.jvm.internal.c {
    public /* synthetic */ Object j;
    public final /* synthetic */ FlashcardsAutoplayService k;
    public int l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public h(FlashcardsAutoplayService flashcardsAutoplayService, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.k = flashcardsAutoplayService;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.j = obj;
        this.l |= Integer.MIN_VALUE;
        int i = FlashcardsAutoplayService.o;
        return this.k.b(null, this);
    }
}
