package androidx.compose.animation.core;

import androidx.compose.runtime.InterfaceC0773a0;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.animation.core.h, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0244h extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ Object k;
    public final /* synthetic */ C0238e l;
    public final /* synthetic */ InterfaceC0773a0 m;
    public final /* synthetic */ InterfaceC0773a0 n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0244h(Object obj, C0238e c0238e, InterfaceC0773a0 interfaceC0773a0, InterfaceC0773a0 interfaceC0773a02, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = obj;
        this.l = c0238e;
        this.m = interfaceC0773a0;
        this.n = interfaceC0773a02;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C0244h(this.k, this.l, this.m, this.n, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C0244h) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        C0244h c0244h;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        C0238e c0238e = this.l;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            if (Intrinsics.b(this.k, ((androidx.compose.runtime.L0) c0238e.e).getValue())) {
                return Unit.a;
            }
            C0253l0 c0253l0 = AbstractC0248j.a;
            InterfaceC0256n interfaceC0256n = (InterfaceC0256n) this.m.getValue();
            this.j = 1;
            c0244h = this;
            if (C0238e.c(this.l, this.k, interfaceC0256n, null, c0244h, 12) == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            androidx.glance.appwidget.protobuf.Z.e(obj);
            c0244h = this;
        }
        C0253l0 c0253l02 = AbstractC0248j.a;
        Function1 function1 = (Function1) c0244h.n.getValue();
        if (function1 != null) {
            function1.invoke(c0238e.d());
        }
        return Unit.a;
    }
}
