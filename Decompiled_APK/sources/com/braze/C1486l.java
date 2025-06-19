package com.braze;

import androidx.glance.appwidget.protobuf.Z;
import com.braze.events.IValueCallback;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.braze.l, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1486l extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ IValueCallback a;
    public final /* synthetic */ Braze b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C1486l(IValueCallback iValueCallback, Braze braze, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.a = iValueCallback;
        this.b = braze;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C1486l(this.a, this.b, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return new C1486l(this.a, this.b, (kotlin.coroutines.h) obj2).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        if (Braze.Companion.isDisabled()) {
            this.a.onError();
            return Unit.a;
        }
        IValueCallback iValueCallback = this.a;
        BrazeUser brazeUser = this.b.brazeUser;
        if (brazeUser != null) {
            iValueCallback.onSuccess(brazeUser);
            return Unit.a;
        }
        Intrinsics.m("brazeUser");
        throw null;
    }
}
