package com.quizlet.remote.model.user.eligibility;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.data.repository.searchexplanations.c;
import com.quizlet.generated.enums.I0;
import com.quizlet.shared.usecase.eligibility.b;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import kotlin.Unit;
import kotlin.collections.U;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class a extends i implements Function2 {
    public int j;
    public final /* synthetic */ Set k;
    public final /* synthetic */ c l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(Set set, c cVar, h hVar) {
        super(2, hVar);
        this.k = set;
        this.l = cVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new a(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((a) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        Set set = this.k;
        if (i == 0) {
            Z.e(obj);
            Set set2 = set;
            ArrayList arrayList = new ArrayList(kotlin.collections.C.q(set2, 10));
            Iterator it2 = set2.iterator();
            while (it2.hasNext()) {
                arrayList.add(((I0) it2.next()).a());
            }
            com.quizlet.shared.usecase.eligibility.c cVar = (com.quizlet.shared.usecase.eligibility.c) this.l.b;
            this.j = 1;
            obj = ((b) cVar).a(arrayList, this);
            if (obj == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        Map map = (Map) obj;
        Set set3 = set;
        int iA = U.a(kotlin.collections.C.q(set3, 10));
        if (iA < 16) {
            iA = 16;
        }
        LinkedHashMap linkedHashMap = new LinkedHashMap(iA);
        for (Object obj2 : set3) {
            Boolean bool = (Boolean) map.get(((I0) obj2).a());
            linkedHashMap.put(obj2, Boolean.valueOf(bool != null ? bool.booleanValue() : false));
        }
        return linkedHashMap;
    }
}
