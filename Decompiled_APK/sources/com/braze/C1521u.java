package com.braze;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;

/* renamed from: com.braze.u, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1521u extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ boolean a;
    public final /* synthetic */ boolean b;
    public final /* synthetic */ Braze c;
    public final /* synthetic */ Function0 d;
    public final /* synthetic */ Function0 e;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C1521u(boolean z, boolean z2, Braze braze, Function0 function0, Function0 function02, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.a = z;
        this.b = z2;
        this.c = braze;
        this.d = function0;
        this.e = function02;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C1521u(this.a, this.b, this.c, this.d, this.e, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C1521u) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws Throwable {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        kotlinx.coroutines.E.D(kotlin.coroutines.n.a, new C1520t(this.a, this.b, this.c, this.d, this.e, null));
        return Unit.a;
    }
}
