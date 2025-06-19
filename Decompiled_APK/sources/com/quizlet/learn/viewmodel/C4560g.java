package com.quizlet.learn.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.generated.enums.C1;
import com.quizlet.generated.enums.E1;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.d0;

/* renamed from: com.quizlet.learn.viewmodel.g, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4560g extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ i k;
    public final /* synthetic */ assistantMode.enums.y l;
    public final /* synthetic */ com.quizlet.studiablemodels.assistantMode.a m;
    public final /* synthetic */ com.quizlet.learn.data.onboarding.B n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4560g(i iVar, assistantMode.enums.y yVar, com.quizlet.studiablemodels.assistantMode.a aVar, com.quizlet.learn.data.onboarding.B b, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = iVar;
        this.l = yVar;
        this.m = aVar;
        this.n = b;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C4560g(this.k, this.l, this.m, this.n, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C4560g) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            i iVar = this.k;
            assistantMode.enums.y yVar = this.l;
            if (yVar != null) {
                com.quizlet.features.infra.studysetting.managers.a aVar2 = iVar.d;
                if (aVar2 == null) {
                    Intrinsics.m("studySettingsManager");
                    throw null;
                }
                aVar2.p(yVar);
            }
            com.quizlet.studiablemodels.assistantMode.a aVar3 = this.m;
            if (aVar3 != null) {
                com.quizlet.features.infra.studysetting.managers.a aVar4 = iVar.d;
                if (aVar4 == null) {
                    Intrinsics.m("studySettingsManager");
                    throw null;
                }
                aVar4.o(aVar3);
            } else {
                iVar.getClass();
            }
            C1 c1 = (yVar == null ? -1 : AbstractC4557d.a[yVar.ordinal()]) == 1 ? C1.START_ALL_AS_FAMILIAR : C1.STANDARD;
            com.quizlet.features.infra.studysetting.managers.a aVar5 = iVar.d;
            if (aVar5 == null) {
                Intrinsics.m("studySettingsManager");
                throw null;
            }
            if (c1 != null) {
                aVar5.n(E1.STUDY_PATH, c1.a());
            } else {
                aVar5.b(E1.STUDY_PATH);
            }
            com.quizlet.features.infra.studysetting.managers.a aVar6 = iVar.d;
            if (aVar6 == null) {
                Intrinsics.m("studySettingsManager");
                throw null;
            }
            aVar6.m(E1.GUIDANCE_DISABLED, false);
            d0 d0Var = iVar.n;
            this.j = 1;
            if (d0Var.emit(this.n, this) == aVar) {
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
