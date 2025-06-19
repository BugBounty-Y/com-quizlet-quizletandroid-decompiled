package com.quizlet.features.notes.detail.viewmodels;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.data.model.EnumC4175w;
import com.quizlet.data.model.EssayInfo;
import com.quizlet.data.model.NotesToValueInfo;
import com.quizlet.data.model.TitleInfo;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes3.dex */
public final class a extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ c k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(c cVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = cVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new a(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((a) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        Object value;
        Object value2;
        Object value3;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        c cVar = this.k;
        s0 s0Var = cVar.f;
        try {
            if (i == 0) {
                Z.e(obj);
                do {
                    value = s0Var.getValue();
                } while (!s0Var.k(value, com.quizlet.features.notes.detail.states.b.a));
                com.quizlet.data.repository.login.a aVar2 = cVar.c;
                String strA = cVar.A();
                this.j = 1;
                obj = aVar2.i(strA, this, false);
                if (obj == aVar) {
                    return aVar;
                }
            } else {
                if (i != 1) {
                    throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                }
                Z.e(obj);
            }
            NotesToValueInfo magicNotes = (NotesToValueInfo) obj;
            Intrinsics.checkNotNullParameter(magicNotes, "magicNotes");
            EssayInfo essayInfo = magicNotes.g;
            if (essayInfo != null) {
                EnumC4175w enumC4175w = essayInfo.b;
                EnumC4175w enumC4175w2 = EnumC4175w.COMPLETE;
                TitleInfo titleInfo = magicNotes.c;
                if (enumC4175w == enumC4175w2) {
                    do {
                        value3 = s0Var.getValue();
                    } while (!s0Var.k(value3, new com.quizlet.features.notes.detail.states.c(essayInfo, titleInfo != null ? titleInfo.c : null)));
                } else {
                    do {
                        value2 = s0Var.getValue();
                    } while (!s0Var.k(value2, new com.quizlet.features.notes.detail.states.a(essayInfo, titleInfo != null ? titleInfo.c : null)));
                }
            }
        } catch (Exception unused) {
            cVar.g.h(com.quizlet.features.notes.detail.events.a.a);
        }
        return Unit.a;
    }
}
