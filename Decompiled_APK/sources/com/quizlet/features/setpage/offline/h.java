package com.quizlet.features.setpage.offline;

import androidx.glance.appwidget.protobuf.Z;
import com.google.android.gms.internal.mlkit_vision_camera.I1;
import com.quizlet.db.data.models.persisted.DBOfflineEntity;
import com.quizlet.generated.enums.G1;
import io.reactivex.rxjava3.core.p;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class h extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ k k;
    public final /* synthetic */ long l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public h(k kVar, long j, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = kVar;
        this.l = j;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new h(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((h) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            final com.quizlet.offline.managers.i iVar = (com.quizlet.offline.managers.i) this.k.c;
            io.reactivex.rxjava3.internal.operators.single.g gVarN = iVar.d.n();
            final long j = this.l;
            io.reactivex.rxjava3.internal.operators.completable.a aVar2 = new io.reactivex.rxjava3.internal.operators.completable.a(5, gVarN, new com.quizlet.offline.managers.g(iVar, j, 1));
            Intrinsics.checkNotNullExpressionValue(aVar2, "flatMapCompletable(...)");
            io.reactivex.rxjava3.internal.operators.completable.a aVar3 = new io.reactivex.rxjava3.internal.operators.completable.a(0, new io.reactivex.rxjava3.internal.operators.completable.h(aVar2, iVar.c, 0), new io.reactivex.rxjava3.core.d() { // from class: com.quizlet.offline.managers.d
                @Override // io.reactivex.rxjava3.core.d
                public final void b(io.reactivex.rxjava3.core.b it2) {
                    Intrinsics.checkNotNullParameter(it2, "it");
                    i iVar2 = iVar;
                    com.quizlet.local.ormlite.models.term.b bVar = iVar2.g;
                    long j2 = j;
                    Long lValueOf = Long.valueOf(j2);
                    G1 g1 = G1.SET;
                    com.quizlet.features.infra.models.b bVar2 = com.quizlet.features.infra.models.b.b;
                    ((com.quizlet.infra.legacysyncengine.managers.i) bVar.b).c(DBOfflineEntity.create(lValueOf, g1, -1));
                    iVar2.j.put(Long.valueOf(j2), com.quizlet.features.infra.models.b.d);
                    iVar2.h.put(j2, p.f(Boolean.FALSE));
                    it2.onComplete();
                }
            });
            Intrinsics.checkNotNullExpressionValue(aVar3, "andThen(...)");
            this.j = 1;
            if (I1.a(aVar3, this) == aVar) {
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
