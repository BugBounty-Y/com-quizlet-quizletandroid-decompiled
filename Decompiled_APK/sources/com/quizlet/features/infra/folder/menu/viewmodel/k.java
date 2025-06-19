package com.quizlet.features.infra.folder.menu.viewmodel;

import androidx.compose.material.ripple.r;
import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.data.model.C4169u;
import com.quizlet.generated.enums.y1;
import java.util.List;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.p;
import kotlin.q;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class k extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ m k;
    public final /* synthetic */ long l;
    public final /* synthetic */ List m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public k(m mVar, long j, List list, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = mVar;
        this.l = j;
        this.m = list;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new k(this.k, this.l, this.m, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((k) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        Object objG;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        m mVar = this.k;
        if (i == 0) {
            Z.e(obj);
            r rVar = mVar.a;
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
            this.j = 1;
            objG = rVar.g(this.l, y1Var, str, this);
            if (objG == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
            objG = ((kotlin.r) obj).a;
        }
        p pVar = kotlin.r.b;
        if (!(objG instanceof q)) {
            List list = this.m;
            long j = this.l;
            m mVar2 = this.k;
            mVar2.y(new com.quizlet.eventlogger.features.learnonboarding.b(mVar2, (C4169u) objG, list, j));
        }
        Throwable thA = kotlin.r.a(objG);
        if (thA != null) {
            mVar.w(thA);
        }
        return Unit.a;
    }
}
