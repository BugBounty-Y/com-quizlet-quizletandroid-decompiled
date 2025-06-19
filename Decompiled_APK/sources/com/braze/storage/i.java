package com.braze.storage;

import androidx.glance.appwidget.protobuf.Z;
import java.util.LinkedHashSet;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class i extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ p a;
    public final /* synthetic */ LinkedHashSet b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public i(p pVar, LinkedHashSet linkedHashSet, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.a = pVar;
        this.b = linkedHashSet;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new i(this.a, this.b, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return new i(this.a, this.b, (kotlin.coroutines.h) obj2).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        this.a.j.edit().putStringSet("test", this.b).apply();
        return Unit.a;
    }
}
