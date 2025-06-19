package com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class m extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ LearnEndingFragment k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public m(LearnEndingFragment learnEndingFragment, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = learnEndingFragment;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new m(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((m) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            com.quizlet.features.infra.ui.feedback.sound.soundeffect.e eVar = this.k.j;
            if (eVar == null) {
                Intrinsics.m("soundEffectPlayer");
                throw null;
            }
            com.quizlet.features.infra.ui.feedback.sound.soundeffect.b bVar = com.quizlet.features.infra.ui.feedback.sound.soundeffect.b.c;
            this.j = 1;
            if (eVar.a(bVar, this) == aVar) {
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
