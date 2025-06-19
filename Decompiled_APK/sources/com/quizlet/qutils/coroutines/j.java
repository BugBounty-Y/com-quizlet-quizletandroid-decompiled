package com.quizlet.qutils.coroutines;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.quizletandroid.ui.common.ads.C;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.q;
import kotlin.r;

/* loaded from: classes3.dex */
public final class j extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ C l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public j(C c, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = c;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        j jVar = new j(this.l, hVar);
        jVar.k = obj;
        return jVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((j) create(new r(((r) obj).a), (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            Object obj2 = ((r) this.k).a;
            if (obj2 instanceof q) {
                Object objA = r.a(obj2);
                if (objA == null) {
                    objA = d.a;
                }
                this.j = 1;
                if (this.l.invoke(objA, this) == aVar) {
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
