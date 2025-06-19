package com.quizlet.explanations.textbook.ui.composables;

import androidx.compose.material3.O3;
import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.features.infra.folder.menu.data.x;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes2.dex */
public final class f extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ O3 l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public f(O3 o3, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = o3;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        f fVar = new f(this.l, hVar);
        fVar.k = obj;
        return fVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((f) create((x) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            com.quizlet.features.infra.folder.menu.composable.i iVar = new com.quizlet.features.infra.folder.menu.composable.i((x) this.k);
            this.j = 1;
            if (this.l.a(iVar, this) == aVar) {
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
