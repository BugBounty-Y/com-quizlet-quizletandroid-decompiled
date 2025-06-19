package com.quizlet.features.flashcards.engine;

import androidx.glance.appwidget.protobuf.Z;
import java.util.ArrayList;
import java.util.List;
import kotlin.Unit;
import kotlin.collections.CollectionsKt;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes2.dex */
public final class f extends i implements Function2 {
    public int j;
    public final /* synthetic */ h k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public f(h hVar, kotlin.coroutines.h hVar2) {
        super(2, hVar2);
        this.k = hVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new f(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((f) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws Throwable {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        h hVar = this.k;
        if (i == 0) {
            Z.e(obj);
            if (hVar.j != null) {
                this.j = 1;
                ArrayList arrayList = ((assistantMode.refactored.studyEngines.b) hVar.b().c).n.a;
                List listW0 = CollectionsKt.w0(arrayList);
                arrayList.clear();
                Object objJ = hVar.j(listW0, this);
                if (objJ != aVar) {
                    objJ = Unit.a;
                }
                if (objJ != aVar) {
                    objJ = Unit.a;
                }
                if (objJ == aVar) {
                    return aVar;
                }
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        com.quizlet.features.infra.basestudy.manager.f.i(hVar.n);
        return Unit.a;
    }
}
