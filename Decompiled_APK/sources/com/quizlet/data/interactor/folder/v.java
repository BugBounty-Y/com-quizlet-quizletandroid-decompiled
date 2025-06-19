package com.quizlet.data.interactor.folder;

import androidx.glance.appwidget.protobuf.Z;
import com.google.android.gms.internal.ads.Ns;
import com.google.android.gms.internal.mlkit_vision_camera.I1;
import kotlin.Unit;
import kotlin.collections.A;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;

/* loaded from: classes2.dex */
public final class v extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ com.quizlet.data.repository.qclass.c k;
    public final /* synthetic */ long l;
    public final /* synthetic */ String m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public v(com.quizlet.data.repository.qclass.c cVar, long j, String str, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = cVar;
        this.l = j;
        this.m = str;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new v(this.k, this.l, this.m, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((v) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i != 0) {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
            return obj;
        }
        Z.e(obj);
        com.quizlet.data.repository.folder.i iVar = (com.quizlet.data.repository.folder.i) this.k.b;
        String name = this.m;
        Intrinsics.checkNotNullParameter(name, "name");
        com.quizlet.local.ormlite.models.bookmark.a aVar2 = (com.quizlet.local.ormlite.models.bookmark.a) iVar.a.b;
        long j = this.l;
        Long id = Long.valueOf(Long.valueOf(j).longValue());
        Intrinsics.checkNotNullParameter(id, "id");
        io.reactivex.rxjava3.core.p pVarB = aVar2.b(A.b(id));
        Intrinsics.checkNotNullParameter(pVarB, "<this>");
        io.reactivex.rxjava3.internal.operators.single.g gVarG = pVarB.g(com.quizlet.data.ext.a.d);
        Intrinsics.checkNotNullExpressionValue(gVarG, "map(...)");
        io.reactivex.rxjava3.internal.operators.single.g gVarE = gVarG.e(new Ns(name, j)).e(new f(iVar, 1));
        Intrinsics.checkNotNullExpressionValue(gVarE, "flatMap(...)");
        this.j = 1;
        Object objB = I1.b(gVarE, this);
        return objB == aVar ? aVar : objB;
    }
}
