package com.braze.storage;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.InterfaceC5025j0;

/* renamed from: com.braze.storage.d, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1517d extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int a;
    public final /* synthetic */ SharedPreferencesC1518e b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C1517d(SharedPreferencesC1518e sharedPreferencesC1518e, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.b = sharedPreferencesC1518e;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C1517d(this.b, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return new C1517d(this.b, (kotlin.coroutines.h) obj2).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.a;
        if (i == 0) {
            Z.e(obj);
            InterfaceC5025j0 interfaceC5025j0 = this.b.c;
            this.a = 1;
            if (interfaceC5025j0.p(this) == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        return Unit.a;
    }
}
