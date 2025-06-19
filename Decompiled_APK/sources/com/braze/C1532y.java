package com.braze;

import androidx.glance.appwidget.protobuf.Z;
import com.braze.managers.u0;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: com.braze.y, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1532y extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ Braze a;
    public final /* synthetic */ String b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C1532y(Braze braze, String str, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.a = braze;
        this.b = str;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C1532y(this.a, this.b, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return new C1532y(this.a, this.b, (kotlin.coroutines.h) obj2).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        return Boolean.valueOf(((u0) this.a.getUdm$android_sdk_base_release()).u.a(this.b));
    }
}
