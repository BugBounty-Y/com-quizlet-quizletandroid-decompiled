package com.quizlet.quizletandroid.initializers.ads;

import android.app.Activity;
import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class b extends i implements Function2 {
    public /* synthetic */ Object j;

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        b bVar = new b(2, hVar);
        bVar.j = obj;
        return bVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((b) create((Activity) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        Activity activity = (Activity) this.j;
        return Boolean.valueOf((activity.isFinishing() || activity.isDestroyed()) ? false : true);
    }
}
