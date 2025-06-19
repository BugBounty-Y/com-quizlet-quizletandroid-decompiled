package com.quizlet.features.flashcards;

import kotlin.jvm.functions.Function0;

/* renamed from: com.quizlet.features.flashcards.d, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C4230d extends kotlin.jvm.internal.r implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ FlashcardsActivity b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C4230d(FlashcardsActivity flashcardsActivity, int i) {
        super(0);
        this.a = i;
        this.b = flashcardsActivity;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return this.b.getDefaultViewModelProviderFactory();
            case 1:
                return this.b.getViewModelStore();
            default:
                return this.b.getDefaultViewModelCreationExtras();
        }
    }
}
