package com.quizlet.quizletandroid.ui.studymodes.testmode.compose;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.G;
import com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.t;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;
import kotlinx.coroutines.flow.Y;
import kotlinx.coroutines.flow.e0;

/* loaded from: classes3.dex */
public final class h extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ t k;
    public final /* synthetic */ G l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public h(t tVar, G g, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = tVar;
        this.l = g;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new h(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((h) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            Y y = this.k.k;
            g gVar = new g(this.l, null);
            this.j = 1;
            if (e0.i(y, gVar, this) == aVar) {
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
