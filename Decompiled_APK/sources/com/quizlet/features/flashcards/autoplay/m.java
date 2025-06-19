package com.quizlet.features.flashcards.autoplay;

/* loaded from: classes2.dex */
public final class m extends kotlin.coroutines.jvm.internal.c {
    public FlashcardsAutoplayService j;
    public String k;
    public boolean l;
    public /* synthetic */ Object m;
    public final /* synthetic */ FlashcardsAutoplayService n;
    public int o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public m(FlashcardsAutoplayService flashcardsAutoplayService, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.n = flashcardsAutoplayService;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.m = obj;
        this.o |= Integer.MIN_VALUE;
        int i = FlashcardsAutoplayService.o;
        return this.n.f(null, this, false);
    }
}
