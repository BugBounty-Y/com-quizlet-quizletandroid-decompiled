package com.braze;

import androidx.glance.appwidget.protobuf.Z;
import com.braze.managers.u0;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: com.braze.d, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1478d extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ Braze a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C1478d(Braze braze, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.a = braze;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C1478d(this.a, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return new C1478d(this.a, (kotlin.coroutines.h) obj2).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        if (((u0) this.a.getUdm$android_sdk_base_release()).m.D()) {
            return ((u0) this.a.getUdm$android_sdk_base_release()).C.a(true);
        }
        return null;
    }
}
