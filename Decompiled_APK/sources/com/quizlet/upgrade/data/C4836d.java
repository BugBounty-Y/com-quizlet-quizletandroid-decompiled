package com.quizlet.upgrade.data;

import androidx.glance.appwidget.protobuf.Z;
import java.util.ArrayList;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: com.quizlet.upgrade.data.d, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4836d extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ ArrayList k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4836d(ArrayList arrayList, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = arrayList;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        C4836d c4836d = new C4836d(this.k, hVar);
        c4836d.j = obj;
        return c4836d;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C4836d) create((com.quizlet.data.model.billing.a) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        this.k.add((com.quizlet.data.model.billing.a) this.j);
        return Unit.a;
    }
}
