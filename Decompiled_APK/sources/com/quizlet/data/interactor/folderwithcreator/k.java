package com.quizlet.data.interactor.folderwithcreator;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.data.model.CreatedFolderWithCreator;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlin.Unit;
import kotlin.collections.CollectionsKt;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes2.dex */
public final class k extends kotlin.coroutines.jvm.internal.i implements kotlin.jvm.functions.c {
    public final /* synthetic */ int j = 0;
    public /* synthetic */ Object k;
    public /* synthetic */ Object l;

    public /* synthetic */ k(int i, kotlin.coroutines.h hVar) {
        super(i, hVar);
    }

    @Override // kotlin.jvm.functions.c
    public final Object invoke(Object obj, Object obj2, Object obj3) {
        switch (this.j) {
            case 0:
                k kVar = new k(3, (kotlin.coroutines.h) obj3);
                kVar.k = (List) obj;
                kVar.l = (List) obj2;
                return kVar.invokeSuspend(Unit.a);
            default:
                k kVar2 = new k((com.quizlet.features.setpage.terms.viewmodel.c) this.l, (kotlin.coroutines.h) obj3);
                kVar2.k = (Throwable) obj2;
                return kVar2.invokeSuspend(Unit.a);
        }
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        s0 s0Var;
        Object value;
        switch (this.j) {
            case 0:
                kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
                Z.e(obj);
                ArrayList arrayListC0 = CollectionsKt.c0((List) this.k, (List) this.l);
                ArrayList arrayList = new ArrayList();
                Iterator it2 = arrayListC0.iterator();
                while (it2.hasNext()) {
                    Object next = it2.next();
                    if (!((CreatedFolderWithCreator) next).a.k()) {
                        arrayList.add(next);
                    }
                }
                return CollectionsKt.n0(arrayList, new e(2));
            default:
                kotlin.coroutines.intrinsics.a aVar2 = kotlin.coroutines.intrinsics.a.a;
                Z.e(obj);
                Throwable th = (Throwable) this.k;
                com.quizlet.features.setpage.terms.viewmodel.c cVar = (com.quizlet.features.setpage.terms.viewmodel.c) this.l;
                cVar.getClass();
                timber.log.c.a.q(th, android.support.v4.media.session.a.g(cVar.i, ")", new StringBuilder("Error loading terms for set with id: (")), new Object[0]);
                do {
                    s0Var = cVar.h;
                    value = s0Var.getValue();
                } while (!s0Var.k(value, com.quizlet.features.setpage.terms.e.a));
                return Unit.a;
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public k(com.quizlet.features.setpage.terms.viewmodel.c cVar, kotlin.coroutines.h hVar) {
        super(3, hVar);
        this.l = cVar;
    }
}
