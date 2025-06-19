package com.braze;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;

/* renamed from: com.braze.w, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1530w extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ boolean a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ boolean c;
    public final /* synthetic */ Braze d;
    public final /* synthetic */ Function2 e;
    public final /* synthetic */ Function0 f;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C1530w(boolean z, Object obj, boolean z2, Braze braze, Function2 function2, Function0 function0, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.a = z;
        this.b = obj;
        this.c = z2;
        this.d = braze;
        this.e = function2;
        this.f = function0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C1530w(this.a, this.b, this.c, this.d, this.e, this.f, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C1530w) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        if (this.a && Braze.Companion.isDisabled()) {
            return this.b;
        }
        return kotlinx.coroutines.E.D(kotlin.coroutines.n.a, new C1529v(this.c, this.d, this.b, this.e, this.f, null));
    }
}
