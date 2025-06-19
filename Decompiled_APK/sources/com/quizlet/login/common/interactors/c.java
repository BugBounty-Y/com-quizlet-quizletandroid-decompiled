package com.quizlet.login.common.interactors;

import androidx.glance.appwidget.protobuf.Z;
import com.google.android.gms.internal.mlkit_vision_camera.I1;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3762x6;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class c extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ d k;
    public final /* synthetic */ String l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(d dVar, String str, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = dVar;
        this.l = str;
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
        if (i != 0) {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
            return obj;
        }
        Z.e(obj);
        com.quizlet.data.repository.login.a aVar2 = (com.quizlet.data.repository.login.a) this.k.b;
        String email = this.l;
        Intrinsics.checkNotNullParameter(email, "email");
        io.reactivex.rxjava3.internal.operators.flowable.b bVar = new io.reactivex.rxjava3.internal.operators.flowable.b(new com.quizlet.data.repository.classfolder.b(5, aVar2, email), 4);
        Intrinsics.checkNotNullExpressionValue(bVar, "defer(...)");
        io.reactivex.rxjava3.internal.operators.single.g gVarC = AbstractC3762x6.c(bVar, (org.slf4j.b) aVar2.c, "Error from checking email validity");
        this.j = 1;
        Object objB = I1.b(gVarC, this);
        return objB == aVar ? aVar : objB;
    }
}
