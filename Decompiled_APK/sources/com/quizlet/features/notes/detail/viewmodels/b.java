package com.quizlet.features.notes.detail.viewmodels;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.data.model.EssayInfo;
import com.quizlet.data.model.R1;
import com.quizlet.eventlogger.model.NotesEventLog;
import com.quizlet.generated.enums.EnumC4465a0;
import com.quizlet.generated.enums.EnumC4503n;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes3.dex */
public final class b extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public String j;
    public int k;
    public final /* synthetic */ EssayInfo l;
    public final /* synthetic */ c m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(EssayInfo essayInfo, c cVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = essayInfo;
        this.m = cVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new b(this.l, this.m, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((b) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        String str;
        s0 s0Var;
        Object value;
        Object value2;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.k;
        EssayInfo essayInfo = this.l;
        c cVar = this.m;
        if (i == 0) {
            Z.e(obj);
            if (essayInfo == null) {
                throw new NoWhenBranchMatchedException();
            }
            com.quizlet.features.notes.logging.f fVar = cVar.e;
            String strA = cVar.A();
            fVar.getClass();
            NotesEventLog.Companion companion = NotesEventLog.b;
            String strA2 = EnumC4465a0.ESSAY_PROMPTS_TRY_AGAIN_CLICKED.a();
            com.quizlet.features.notes.logging.c cVar2 = new com.quizlet.features.notes.logging.c(strA, 20);
            EnumC4503n enumC4503n = com.quizlet.features.notes.logging.a.c;
            companion.getClass();
            fVar.a(NotesEventLog.Companion.a(enumC4503n, strA2, cVar2));
            Object value3 = cVar.f.getValue();
            com.quizlet.features.notes.detail.states.a aVar2 = value3 instanceof com.quizlet.features.notes.detail.states.a ? (com.quizlet.features.notes.detail.states.a) value3 : null;
            String str2 = aVar2 != null ? aVar2.b : null;
            try {
                com.google.firebase.messaging.p pVar = cVar.d;
                this.j = str2;
                this.k = 1;
                Object objT = pVar.t(essayInfo, this);
                if (objT == aVar) {
                    return aVar;
                }
                str = str2;
                obj = objT;
            } catch (Exception unused) {
                str = str2;
                s0Var = cVar.f;
                do {
                    value = s0Var.getValue();
                } while (!s0Var.k(value, new com.quizlet.features.notes.detail.states.a(essayInfo, str)));
                return Unit.a;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            str = this.j;
            try {
                Z.e(obj);
            } catch (Exception unused2) {
                s0Var = cVar.f;
                do {
                    value = s0Var.getValue();
                } while (!s0Var.k(value, new com.quizlet.features.notes.detail.states.a(essayInfo, str)));
                return Unit.a;
            }
        }
        R1 r1 = (R1) obj;
        s0 s0Var2 = cVar.f;
        do {
            value2 = s0Var2.getValue();
        } while (!s0Var2.k(value2, new com.quizlet.features.notes.detail.states.c(r1, str)));
        return Unit.a;
    }
}
