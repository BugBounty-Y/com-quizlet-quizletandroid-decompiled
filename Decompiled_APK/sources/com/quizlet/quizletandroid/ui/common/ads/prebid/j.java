package com.quizlet.quizletandroid.ui.common.ads.prebid;

import android.view.View;
import androidx.glance.appwidget.protobuf.Z;
import java.util.Iterator;
import java.util.List;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class j extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ boolean k;
    public final /* synthetic */ m l;
    public final /* synthetic */ List m;
    public final /* synthetic */ Function0 n;
    public final /* synthetic */ Function1 o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public j(boolean z, m mVar, List list, Function0 function0, Function1 function1, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = z;
        this.l = mVar;
        this.m = list;
        this.n = function0;
        this.o = function1;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        j jVar = new j(this.k, this.l, this.m, this.n, this.o, hVar);
        jVar.j = obj;
        return jVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((j) create((com.quizlet.data.model.ads.g) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        com.quizlet.data.model.ads.g gVar = (com.quizlet.data.model.ads.g) this.j;
        timber.log.c.a.a("Banner Event: " + gVar, new Object[0]);
        boolean z = gVar instanceof com.quizlet.data.model.ads.b;
        List list = this.m;
        boolean z2 = this.k;
        if (z) {
            if (z2) {
                Iterator it2 = list.iterator();
                while (it2.hasNext()) {
                    ((View) it2.next()).setVisibility(0);
                }
            }
            this.n.invoke();
        } else if (gVar instanceof com.quizlet.data.model.ads.a) {
            if (z2) {
                Iterator it3 = list.iterator();
                while (it3.hasNext()) {
                    ((View) it3.next()).setVisibility(8);
                }
            }
            this.o.invoke(((com.quizlet.data.model.ads.a) gVar).a);
        }
        return Unit.a;
    }
}
