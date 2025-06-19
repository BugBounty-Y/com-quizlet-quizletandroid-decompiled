package com.quizlet.search.viewmodels;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.eventlogger.features.search.SearchEventLogger;
import com.quizlet.eventlogger.features.search.SearchType;
import java.util.ArrayList;
import java.util.List;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.AbstractC5040y;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes3.dex */
public final class q extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ r k;
    public final /* synthetic */ String l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public q(r rVar, String str, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = rVar;
        this.l = str;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new q(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((q) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws Throwable {
        s0 s0Var;
        Object value;
        List list;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        r rVar = this.k;
        if (i == 0) {
            Z.e(obj);
            this.j = 1;
            com.quizlet.data.repository.folderwithcreatorinclass.e eVar = rVar.b;
            eVar.getClass();
            obj = kotlinx.coroutines.E.J((AbstractC5040y) eVar.d, new com.quizlet.search.data.blended.f(eVar, this.l, null), this);
            if (obj == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        com.quizlet.search.data.blended.a aVar2 = (com.quizlet.search.data.blended.a) obj;
        rVar.h = true;
        do {
            s0Var = rVar.e;
            value = s0Var.getValue();
            list = aVar2.a;
            ArrayList arrayList = new ArrayList();
            for (Object obj2 : list) {
                if (obj2 instanceof com.quizlet.ui.models.search.b) {
                    arrayList.add(obj2);
                }
            }
            rVar.g = arrayList.size() == 1;
            String str = aVar2.b;
            if (str.length() > 0) {
                SearchEventLogger searchEventLogger = rVar.c;
                SearchType searchType = rVar.d;
                searchEventLogger.r(searchType, str);
                if (rVar.h) {
                    rVar.h = false;
                    if (rVar.g) {
                        searchEventLogger.z(searchType, str);
                    } else {
                        searchEventLogger.u(searchType, str);
                    }
                }
                List list2 = aVar2.c;
                if (!list2.isEmpty()) {
                    searchEventLogger.q(list2);
                }
                searchEventLogger.s();
            }
        } while (!s0Var.k(value, new com.quizlet.search.data.blended.h(list)));
        return Unit.a;
    }
}
