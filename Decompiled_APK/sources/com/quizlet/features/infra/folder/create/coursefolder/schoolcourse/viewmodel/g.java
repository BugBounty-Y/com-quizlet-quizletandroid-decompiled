package com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.p;
import kotlin.q;
import kotlin.r;
import kotlinx.coroutines.C;
import kotlinx.coroutines.flow.d0;

/* loaded from: classes3.dex */
public final class g extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public Object j;
    public o k;
    public com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.e l;
    public int m;
    public final /* synthetic */ o n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public g(o oVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.n = oVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new g(this.n, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((g) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        Object objD;
        com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.e eVar;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.m;
        o oVar = this.n;
        if (i == 0) {
            Z.e(obj);
            com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.usecase.i iVar = oVar.c;
            this.m = 1;
            objD = iVar.d(this);
            if (objD != aVar) {
            }
            return aVar;
        }
        if (i != 1) {
            if (i != 2) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            eVar = this.l;
            oVar = this.k;
            Z.e(obj);
            oVar.A(eVar);
            return Unit.a;
        }
        Z.e(obj);
        objD = ((r) obj).a;
        p pVar = r.b;
        if (!(objD instanceof q)) {
            com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.e eVar2 = (com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.e) objD;
            oVar.m = eVar2;
            if (eVar2 != null) {
                oVar.g.n();
                d0 d0Var = oVar.j;
                c cVar = new c(eVar2.a, eVar2.b);
                this.j = objD;
                this.k = oVar;
                this.l = eVar2;
                this.m = 2;
                if (d0Var.emit(cVar, this) != aVar) {
                    eVar = eVar2;
                    oVar.A(eVar);
                }
                return aVar;
            }
            oVar.B(true);
        }
        return Unit.a;
    }
}
