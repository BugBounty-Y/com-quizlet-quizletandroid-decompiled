package com.quizlet.features.flashcards.views.composables;

import androidx.compose.runtime.InterfaceC0773a0;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3261t0;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.AbstractC4958q;
import kotlin.jvm.internal.C4956o;

/* loaded from: classes2.dex */
public final /* synthetic */ class i extends C4956o implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Function0 b;
    public final /* synthetic */ InterfaceC0773a0 c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public i(Function0 function0, InterfaceC0773a0 interfaceC0773a0, int i) {
        super(0, AbstractC4958q.class, "onCardFlip", "FlashcardsCardView_Xu_d2DI$onCardFlip(Lkotlin/jvm/functions/Function0;Landroidx/compose/runtime/MutableState;)V", 0);
        this.a = i;
        switch (i) {
            case 1:
                this.b = function0;
                this.c = interfaceC0773a0;
                super(0, AbstractC4958q.class, "onCardFlip", "FlashcardsCardView_Xu_d2DI$onCardFlip(Lkotlin/jvm/functions/Function0;Landroidx/compose/runtime/MutableState;)V", 0);
                break;
            default:
                this.b = function0;
                this.c = interfaceC0773a0;
                break;
        }
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                AbstractC3261t0.b(this.c, this.b);
                break;
            default:
                AbstractC3261t0.b(this.c, this.b);
                break;
        }
        return Unit.a;
    }
}
