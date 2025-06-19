package com.quizlet.features.folders.viewmodel;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3409x1;
import com.quizlet.features.folders.data.C4314w0;
import com.quizlet.features.folders.data.C4316x0;
import com.quizlet.features.folders.data.InterfaceC4318y0;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import kotlin.Pair;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.C4942a;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.features.folders.viewmodel.i, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final /* synthetic */ class C4328i extends C4942a implements kotlin.jvm.functions.c {
    @Override // kotlin.jvm.functions.c
    public final Object invoke(Object obj, Object obj2, Object obj3) {
        List<com.quizlet.ui.models.content.listitem.o> list = (List) obj;
        InterfaceC4318y0 interfaceC4318y0 = (InterfaceC4318y0) obj2;
        ((N) this.a).getClass();
        ArrayList arrayList = new ArrayList(kotlin.collections.C.q(list, 10));
        for (com.quizlet.ui.models.content.listitem.o oVar : list) {
            arrayList.add(new Pair(oVar.d(), oVar.b()));
        }
        Set setA0 = CollectionsKt.A0(arrayList);
        C4316x0 c4316x0 = C4316x0.a;
        if (!(interfaceC4318y0 instanceof C4314w0)) {
            return c4316x0;
        }
        C4314w0 c4314w0 = (C4314w0) interfaceC4318y0;
        kotlinx.collections.immutable.b recs = c4314w0.b;
        Intrinsics.checkNotNullParameter(recs, "recs");
        ArrayList arrayList2 = new ArrayList();
        for (Object obj4 : recs) {
            com.quizlet.ui.models.content.listitem.o oVar2 = (com.quizlet.ui.models.content.listitem.o) obj4;
            if (!setA0.contains(new Pair(oVar2.d(), oVar2.b()))) {
                arrayList2.add(obj4);
            }
        }
        HashSet hashSet = new HashSet();
        ArrayList arrayList3 = new ArrayList();
        Iterator it2 = arrayList2.iterator();
        while (it2.hasNext()) {
            Object next = it2.next();
            com.quizlet.ui.models.content.listitem.o oVar3 = (com.quizlet.ui.models.content.listitem.o) next;
            if (hashSet.add(new Pair(oVar3.b(), oVar3.d()))) {
                arrayList3.add(next);
            }
        }
        kotlinx.collections.immutable.b bVarI = AbstractC3409x1.i(arrayList3);
        return !bVarI.isEmpty() ? new C4314w0(c4314w0.a, bVarI) : c4316x0;
    }
}
