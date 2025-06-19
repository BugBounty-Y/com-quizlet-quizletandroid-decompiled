package com.quizlet.data.interactor.folder;

import androidx.compose.foundation.text.z0;
import androidx.glance.appwidget.protobuf.Z;
import com.google.android.gms.internal.mlkit_vision_camera.I1;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3770y6;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes2.dex */
public final class m extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ androidx.work.impl.model.e k;
    public final /* synthetic */ long l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public m(androidx.work.impl.model.e eVar, long j, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = eVar;
        this.l = j;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new m(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((m) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
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
        io.reactivex.rxjava3.internal.operators.single.g gVarC = AbstractC3770y6.c(new z0(1, (com.quizlet.data.repository.folder.i) this.k.b, com.quizlet.data.repository.folder.i.class, "deleteFoldersRemote", "deleteFoldersRemote(Ljava/util/List;)Lio/reactivex/rxjava3/core/Single;", 0, 11), Long.valueOf(this.l));
        this.j = 1;
        Object objB = I1.b(gVarC, this);
        return objB == aVar ? aVar : objB;
    }
}
