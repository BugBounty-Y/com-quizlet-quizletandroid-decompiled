package com.quizlet.shared.repository.folders;

import androidx.glance.appwidget.protobuf.Z;
import java.util.ArrayList;
import kotlin.Unit;
import kotlin.collections.CollectionsKt;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class b extends i implements Function2 {
    public int j;
    public final /* synthetic */ d k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(d dVar, h hVar) {
        super(2, hVar);
        this.k = dVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new b(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((b) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            com.quizlet.shared.cache.a aVar2 = (com.quizlet.shared.cache.a) this.k.c;
            this.j = 1;
            obj = aVar2.a(this);
            if (obj == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        ArrayList arrayList = new ArrayList();
        for (serialization.e eVar : (Iterable) obj) {
            com.quizlet.shared.models.api.folders.a aVar3 = eVar instanceof com.quizlet.shared.models.api.folders.a ? (com.quizlet.shared.models.api.folders.a) eVar : null;
            if (aVar3 != null) {
                arrayList.add(aVar3);
            }
        }
        return CollectionsKt.A0(arrayList);
    }
}
