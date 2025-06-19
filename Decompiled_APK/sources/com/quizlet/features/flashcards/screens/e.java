package com.quizlet.features.flashcards.screens;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes2.dex */
public final class e extends i implements Function2 {
    public int j;
    public final /* synthetic */ com.quizlet.features.infra.ui.feedback.sound.soundeffect.b k;
    public final /* synthetic */ com.quizlet.features.infra.ui.feedback.sound.soundeffect.e l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public e(com.quizlet.features.infra.ui.feedback.sound.soundeffect.b bVar, com.quizlet.features.infra.ui.feedback.sound.soundeffect.e eVar, h hVar) {
        super(2, hVar);
        this.k = bVar;
        this.l = eVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new e(this.k, this.l, hVar);
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
            com.quizlet.features.infra.ui.feedback.sound.soundeffect.b bVar = this.k;
            if (bVar != null) {
                this.j = 1;
                if (this.l.a(bVar, this) == aVar) {
                    return aVar;
                }
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
