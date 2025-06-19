package com.quizlet.data.interactor.user.eligibility;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.data.repository.user.eligibility.g;
import java.io.Serializable;
import java.util.Set;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function1;

/* loaded from: classes2.dex */
public final class a extends i implements Function1 {
    public int j;
    public final /* synthetic */ com.quizlet.data.repository.activitycenter.b k;
    public final /* synthetic */ Set l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(com.quizlet.data.repository.activitycenter.b bVar, Set set, h hVar) {
        super(1, hVar);
        this.k = bVar;
        this.l = set;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(h hVar) {
        return new a(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        return ((a) create((h) obj)).invokeSuspend(Unit.a);
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
        g gVar = (g) this.k.b;
        this.j = 1;
        Serializable serializableB = gVar.b(this.l, this);
        return serializableB == aVar ? aVar : serializableB;
    }
}
