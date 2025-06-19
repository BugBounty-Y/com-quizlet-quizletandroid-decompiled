package com.braze.events;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class c extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ IEventSubscriber a;
    public final /* synthetic */ Object b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(IEventSubscriber iEventSubscriber, Object obj, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.a = iEventSubscriber;
        this.b = obj;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new c(this.a, this.b, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return new c(this.a, this.b, (kotlin.coroutines.h) obj2).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        this.a.trigger(this.b);
        return Unit.a;
    }
}
