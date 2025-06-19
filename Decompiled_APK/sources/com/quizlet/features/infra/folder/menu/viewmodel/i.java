package com.quizlet.features.infra.folder.menu.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.generated.enums.y1;
import kotlin.Unit;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class i extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ m k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public i(m mVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = mVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new i(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((i) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            m mVar = this.k;
            Object value = mVar.g.getValue();
            if (!(((com.quizlet.features.infra.folder.menu.screenstates.d) value) instanceof com.quizlet.features.infra.folder.menu.screenstates.c)) {
                value = null;
            }
            com.quizlet.features.infra.folder.menu.screenstates.d dVar = (com.quizlet.features.infra.folder.menu.screenstates.d) value;
            if (dVar != null) {
                kotlinx.collections.immutable.c cVarT = m.t(dVar.a());
                kotlinx.collections.immutable.c cVarB = dVar.b();
                String str = mVar.m;
                if (str == null) {
                    Intrinsics.m("studyMaterialId");
                    throw null;
                }
                y1 y1Var = mVar.l;
                if (y1Var == null) {
                    Intrinsics.m("studyMaterialType");
                    throw null;
                }
                com.quizlet.data.interactor.folderstudymaterial.e eVar = new com.quizlet.data.interactor.folderstudymaterial.e(str, y1Var, CollectionsKt.w0(cVarB), CollectionsKt.w0(cVarT));
                mVar.p();
                String str2 = mVar.m;
                if (str2 == null) {
                    Intrinsics.m("studyMaterialId");
                    throw null;
                }
                y1 y1Var2 = mVar.l;
                if (y1Var2 == null) {
                    Intrinsics.m("studyMaterialType");
                    throw null;
                }
                mVar.b.C(str2, y1Var2);
                this.j = 1;
                if (m.a(mVar, "", eVar, this) == aVar) {
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
