package com.quizlet.features.folders.changetags.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3409x1;
import com.quizlet.features.folders.changetags.data.f;
import com.quizlet.generated.enums.y1;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlin.Unit;
import kotlin.collections.CollectionsKt;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes3.dex */
public final class c extends i implements Function2 {
    public int j;
    public final /* synthetic */ d k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(d dVar, h hVar) {
        super(2, hVar);
        this.k = dVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new c(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((c) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlinx.collections.immutable.c cVar;
        s0 s0Var;
        Object value;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            d dVar = this.k;
            f fVar = (f) dVar.h.getValue();
            String str = dVar.e;
            y1 y1Var = dVar.f;
            if (str == null || y1Var == null) {
                return Unit.a;
            }
            kotlinx.collections.immutable.c cVarB = d.B(fVar.c.d);
            List list = fVar.c.d;
            ArrayList arrayList = new ArrayList();
            for (Object obj2 : list) {
                if (obj2 instanceof com.quizlet.features.infra.folder.menu.data.e) {
                    arrayList.add(obj2);
                }
            }
            ArrayList arrayList2 = new ArrayList();
            Iterator it2 = arrayList.iterator();
            while (true) {
                boolean zHasNext = it2.hasNext();
                cVar = fVar.b;
                if (!zHasNext) {
                    break;
                }
                Object next = it2.next();
                if (cVar.contains(Long.valueOf(((com.quizlet.features.infra.folder.menu.data.e) next).b))) {
                    arrayList2.add(next);
                }
            }
            ArrayList arrayList3 = new ArrayList(kotlin.collections.C.q(arrayList2, 10));
            Iterator it3 = arrayList2.iterator();
            while (it3.hasNext()) {
                arrayList3.add(((com.quizlet.features.infra.folder.menu.data.e) it3.next()).c);
            }
            kotlinx.collections.immutable.c cVarJ = AbstractC3409x1.j(arrayList3);
            com.quizlet.data.interactor.folderstudymaterial.e eVar = new com.quizlet.data.interactor.folderstudymaterial.e(str, y1Var, CollectionsKt.w0(cVar), CollectionsKt.w0(cVarB));
            do {
                s0Var = dVar.h;
                value = s0Var.getValue();
            } while (!s0Var.k(value, f.a((f) value, false, null, null, true, 7)));
            this.j = 1;
            if (d.A(dVar, eVar, cVarJ, this) == aVar) {
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
