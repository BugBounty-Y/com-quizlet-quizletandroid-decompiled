package com.quizlet.features.folders.addtofolder.composables;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.assembly.compose.modals.x;
import com.quizlet.features.folders.data.S;
import java.util.List;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class n extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ Function1 k;
    public final /* synthetic */ x l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public n(x xVar, kotlin.coroutines.h hVar, Function1 function1) {
        super(2, hVar);
        this.k = function1;
        this.l = xVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        n nVar = new n(this.l, hVar, this.k);
        nVar.j = obj;
        return nVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((n) create((List) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        this.k.invoke(new S((List) this.j));
        this.l.a();
        return Unit.a;
    }
}
