package com.braze.storage;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: com.braze.storage.c, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1516c extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ SharedPreferencesC1518e a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C1516c(SharedPreferencesC1518e sharedPreferencesC1518e, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.a = sharedPreferencesC1518e;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C1516c(this.a, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return new C1516c(this.a, (kotlin.coroutines.h) obj2).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        this.a.a.getSharedPreferences("persistent.com.appboy.storage.sdk_enabled_cache", 0);
        return Unit.a;
    }
}
