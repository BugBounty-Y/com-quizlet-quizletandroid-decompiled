package com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;
import kotlinx.coroutines.flow.e0;

/* loaded from: classes3.dex */
public final class e extends i implements Function2 {
    public int j;
    public final /* synthetic */ g k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public e(g gVar, h hVar) {
        super(2, hVar);
        this.k = gVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new e(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((e) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            g gVar = this.k;
            com.quizlet.features.flashcards.helpers.d dVar = new com.quizlet.features.flashcards.helpers.d(new kotlinx.coroutines.flow.Z(gVar.j.z), 5);
            d dVar2 = new d(gVar, null);
            this.j = 1;
            if (e0.i(dVar, dVar2, this) == aVar) {
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
