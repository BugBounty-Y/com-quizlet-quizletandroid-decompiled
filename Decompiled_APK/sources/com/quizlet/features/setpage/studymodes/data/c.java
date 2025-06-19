package com.quizlet.features.setpage.studymodes.data;

import androidx.glance.appwidget.protobuf.Z;
import com.google.android.gms.internal.mlkit_vision_camera.I1;
import com.quizlet.generated.enums.A1;
import com.quizlet.infra.legacysyncengine.datasources.p;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class c extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ com.quizlet.remote.model.notes.e k;
    public final /* synthetic */ long l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(com.quizlet.remote.model.notes.e eVar, long j, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = eVar;
        this.l = j;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new c(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((c) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            com.quizlet.data.repository.searchexplanations.c cVar = (com.quizlet.data.repository.searchexplanations.c) this.k.e;
            p pVar = (p) cVar.c;
            if (pVar == null) {
                com.quizlet.quizletandroid.ui.group.data.b bVar = (com.quizlet.quizletandroid.ui.group.data.b) cVar.b;
                p pVar2 = new p(bVar.a, this.l, bVar.b, A1.FLASHCARDS);
                cVar.c = pVar2;
                pVar = pVar2;
            }
            pVar.d();
            this.j = 1;
            if (I1.a((io.reactivex.rxjava3.internal.operators.completable.c) pVar.g, this) == aVar) {
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
