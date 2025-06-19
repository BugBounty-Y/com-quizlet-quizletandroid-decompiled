package com.quizlet.data.repository.studysetwithcreator;

import com.quizlet.data.model.Z1;
import io.reactivex.rxjava3.core.i;
import io.reactivex.rxjava3.functions.h;
import io.reactivex.rxjava3.internal.operators.observable.E;
import java.util.ArrayList;
import java.util.List;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class c implements h {
    public static final c b = new c(0);
    public static final c c = new c(1);
    public final /* synthetic */ int a;

    public /* synthetic */ c(int i) {
        this.a = i;
    }

    @Override // io.reactivex.rxjava3.functions.h
    public final Object apply(Object obj) {
        switch (this.a) {
            case 0:
                List list = (List) obj;
                ArrayList arrayListM = assistantMode.refactored.a.m("studySets", list);
                for (Object obj2 : list) {
                    if (!((Z1) obj2).a.y) {
                        arrayListM.add(obj2);
                    }
                }
                return arrayListM;
            default:
                List list2 = (List) obj;
                Intrinsics.checkNotNullParameter(list2, "list");
                Z1 z1 = (Z1) CollectionsKt.firstOrNull(list2);
                return z1 != null ? i.p(z1) : E.a;
        }
    }
}
