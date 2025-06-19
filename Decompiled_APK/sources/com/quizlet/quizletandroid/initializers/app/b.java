package com.quizlet.quizletandroid.initializers.app;

import android.content.Context;
import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.quizletandroid.u;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class b extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ Context j;
    public final /* synthetic */ u k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(Context context, u uVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.j = context;
        this.k = uVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new b(this.j, this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((b) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        this.j.getApplicationContext().registerComponentCallbacks((com.quizlet.infra.legacysyncengine.net.c) this.k.Q.get());
        return Unit.a;
    }
}
