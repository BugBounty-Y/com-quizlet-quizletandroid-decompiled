package com.quizlet.features.flashcards.autoplay;

import androidx.glance.appwidget.protobuf.Z;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3146g0;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes2.dex */
public final class k extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ FlashcardsAutoplayService l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public k(FlashcardsAutoplayService flashcardsAutoplayService, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = flashcardsAutoplayService;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        k kVar = new k(this.l, hVar);
        kVar.k = obj;
        return kVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((k) create((com.quizlet.features.flashcards.data.e) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            com.quizlet.features.flashcards.data.e eVar = (com.quizlet.features.flashcards.data.e) this.k;
            AbstractC3146g0 abstractC3146g0 = eVar != null ? eVar.a : null;
            this.j = 1;
            if (FlashcardsAutoplayService.a(this.l, abstractC3146g0, this) == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        return Unit.a;
    }
}
