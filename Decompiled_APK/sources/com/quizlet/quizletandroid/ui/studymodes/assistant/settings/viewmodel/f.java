package com.quizlet.quizletandroid.ui.studymodes.assistant.settings.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.LearnSettingsUpdateData;
import com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.m;
import com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.o;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes3.dex */
public final class f extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ i k;
    public final /* synthetic */ LearnSettingsUpdateData l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public f(i iVar, LearnSettingsUpdateData learnSettingsUpdateData, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = iVar;
        this.l = learnSettingsUpdateData;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new f(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((f) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        s0 s0Var;
        Object value;
        o oVar;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        i iVar = this.k;
        if (i == 0) {
            Z.e(obj);
            this.j = 1;
            obj = iVar.h.k(iVar.r, this);
            if (obj == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        if (((Boolean) obj).booleanValue()) {
            do {
                s0Var = iVar.p;
                value = s0Var.getValue();
                oVar = (o) value;
                Intrinsics.e(oVar, "null cannot be cast to non-null type com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.LearnSettingsUiState.Content");
            } while (!s0Var.k(value, m.a((m) oVar, true, 260095)));
        } else {
            iVar.F(this.l);
        }
        return Unit.a;
    }
}
