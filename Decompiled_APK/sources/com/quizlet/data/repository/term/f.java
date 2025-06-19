package com.quizlet.data.repository.term;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.data.model.J0;
import com.quizlet.data.model.N;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlin.r;
import kotlinx.coroutines.C;

/* loaded from: classes2.dex */
public final class f extends i implements Function2 {
    public int j;
    public final /* synthetic */ g k;
    public final /* synthetic */ long l;
    public final /* synthetic */ int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public f(g gVar, long j, int i, h hVar) {
        super(2, hVar);
        this.k = gVar;
        this.l = j;
        this.m = i;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new f(this.k, this.l, this.m, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((f) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        Object objJ;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            com.quizlet.data.repository.classfolder.e eVar = this.k.b;
            J0 j0 = new J0(this.m, 11);
            this.j = 1;
            objJ = eVar.j(this.l, j0, this);
            if (objJ == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
            objJ = ((r) obj).a;
        }
        Z.e(objJ);
        return ((N) objJ).a;
    }
}
