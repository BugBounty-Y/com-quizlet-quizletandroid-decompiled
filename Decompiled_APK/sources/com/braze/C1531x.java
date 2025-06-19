package com.braze;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;

/* renamed from: com.braze.x, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1531x extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int a;
    public final /* synthetic */ boolean b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ boolean d;
    public final /* synthetic */ Braze e;
    public final /* synthetic */ Function2 f;
    public final /* synthetic */ Function0 g;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C1531x(boolean z, Object obj, boolean z2, Braze braze, Function2 function2, Function0 function0, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.b = z;
        this.c = obj;
        this.d = z2;
        this.e = braze;
        this.f = function2;
        this.g = function0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C1531x(this.b, this.c, this.d, this.e, this.f, this.g, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C1531x) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws Throwable {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.a;
        if (i != 0) {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
            return obj;
        }
        Z.e(obj);
        kotlinx.coroutines.I iF = kotlinx.coroutines.E.f(com.braze.coroutine.f.a, null, new C1530w(this.b, this.c, this.d, this.e, this.f, this.g, null), 3);
        this.a = 1;
        Object objW = iF.w(this);
        return objW == aVar ? aVar : objW;
    }
}
