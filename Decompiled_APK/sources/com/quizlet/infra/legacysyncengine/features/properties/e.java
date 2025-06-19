package com.quizlet.infra.legacysyncengine.features.properties;

import com.quizlet.data.model.E;
import com.quizlet.db.data.models.persisted.DBUser;
import io.reactivex.rxjava3.functions.h;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlin.collections.C;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class e implements h {
    public final /* synthetic */ int a = 0;
    public final /* synthetic */ List b;

    public e(List list) {
        this.b = list;
    }

    @Override // io.reactivex.rxjava3.functions.h
    public final Object apply(Object obj) {
        switch (this.a) {
            case 0:
                List list = (List) obj;
                ArrayList arrayListM = assistantMode.refactored.a.m("classMemberships", list);
                for (Object obj2 : list) {
                    if (((E) obj2).i) {
                        arrayListM.add(obj2);
                    }
                }
                ArrayList arrayList = new ArrayList(C.q(arrayListM, 10));
                Iterator it2 = arrayListM.iterator();
                while (it2.hasNext()) {
                    arrayList.add(Long.valueOf(((E) it2.next()).b));
                }
                return Boolean.valueOf(!CollectionsKt.Q(arrayList, this.b).isEmpty());
            default:
                Boolean it3 = (Boolean) obj;
                Intrinsics.checkNotNullParameter(it3, "it");
                List list2 = this.b;
                Intrinsics.d(list2);
                ArrayList arrayList2 = new ArrayList(C.q(list2, 10));
                Iterator it4 = list2.iterator();
                while (it4.hasNext()) {
                    arrayList2.add(retrofit2.adapter.rxjava3.d.s((DBUser) it4.next()));
                }
                return arrayList2;
        }
    }

    public e(List list, com.quizlet.data.repository.user.a aVar) {
        this.b = list;
    }
}
