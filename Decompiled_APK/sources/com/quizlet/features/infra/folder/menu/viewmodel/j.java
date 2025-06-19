package com.quizlet.features.infra.folder.menu.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.generated.enums.y1;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class j extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ m k;
    public final /* synthetic */ String l;
    public final /* synthetic */ y1 m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public j(m mVar, String str, y1 y1Var, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = mVar;
        this.l = str;
        this.m = y1Var;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new j(this.k, this.l, this.m, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((j) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            m mVar = this.k;
            String str = this.l;
            mVar.m = str;
            y1 y1Var = this.m;
            mVar.l = y1Var;
            this.j = 1;
            if (m.d(mVar, str, y1Var, this) == aVar) {
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
