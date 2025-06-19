package com.quizlet.features.folders.composables;

import android.content.Context;
import com.quizlet.features.folders.data.C4291k0;
import com.quizlet.features.folders.data.C4293l0;
import com.quizlet.features.folders.data.C4295m0;
import com.quizlet.features.folders.data.C4297n0;
import com.quizlet.features.folders.data.C4299o0;
import com.quizlet.features.folders.data.C4301p0;
import com.quizlet.features.folders.data.C4303q0;
import com.quizlet.features.folders.data.C4304r0;
import com.quizlet.features.folders.data.C4306s0;
import com.quizlet.features.folders.data.C4308t0;
import com.quizlet.features.folders.data.C4310u0;
import com.quizlet.features.folders.data.InterfaceC4312v0;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.features.folders.composables.z, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4269z extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ com.quizlet.features.folders.navigation.b k;
    public final /* synthetic */ androidx.activity.compose.o l;
    public final /* synthetic */ kotlinx.coroutines.C m;
    public final /* synthetic */ Function0 n;
    public final /* synthetic */ Context o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4269z(com.quizlet.features.folders.navigation.b bVar, androidx.activity.compose.o oVar, kotlinx.coroutines.C c, Function0 function0, Context context, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = bVar;
        this.l = oVar;
        this.m = c;
        this.n = function0;
        this.o = context;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        C4269z c4269z = new C4269z(this.k, this.l, this.m, this.n, this.o, hVar);
        c4269z.j = obj;
        return c4269z;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C4269z) create((InterfaceC4312v0) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        androidx.glance.appwidget.protobuf.Z.e(obj);
        InterfaceC4312v0 interfaceC4312v0 = (InterfaceC4312v0) this.j;
        boolean z = interfaceC4312v0 instanceof C4310u0;
        com.quizlet.features.folders.navigation.b bVar = this.k;
        if (z) {
            bVar.y(((C4310u0) interfaceC4312v0).a);
            Unit unit = Unit.a;
        } else if (interfaceC4312v0 instanceof C4303q0) {
            bVar.z(((C4303q0) interfaceC4312v0).a);
            Unit unit2 = Unit.a;
        } else if (interfaceC4312v0 instanceof C4297n0) {
            bVar.v(((C4297n0) interfaceC4312v0).a);
            Unit unit3 = Unit.a;
        } else if (interfaceC4312v0 instanceof C4304r0) {
            bVar.l(((C4304r0) interfaceC4312v0).a);
            Unit unit4 = Unit.a;
        } else if (interfaceC4312v0 instanceof C4306s0) {
            bVar.A(((C4306s0) interfaceC4312v0).a);
            Unit unit5 = Unit.a;
        } else if (interfaceC4312v0 instanceof C4295m0) {
            bVar.E(((C4295m0) interfaceC4312v0).a);
            Unit unit6 = Unit.a;
        } else if (interfaceC4312v0 instanceof C4301p0) {
            bVar.n(((C4301p0) interfaceC4312v0).a);
            Unit unit7 = Unit.a;
        } else {
            boolean z2 = interfaceC4312v0 instanceof C4293l0;
            androidx.activity.compose.o oVar = this.l;
            if (z2) {
                bVar.o(oVar, ((C4293l0) interfaceC4312v0).a);
                Unit unit8 = Unit.a;
            } else if (interfaceC4312v0 instanceof C4308t0) {
                bVar.t(oVar, ((C4308t0) interfaceC4312v0).a);
                Unit unit9 = Unit.a;
            } else if (interfaceC4312v0 instanceof C4299o0) {
                kotlinx.coroutines.E.A(this.m, null, null, new C(bVar, interfaceC4312v0, this.o, null), 3);
            } else {
                if (!Intrinsics.b(interfaceC4312v0, C4291k0.a)) {
                    throw new NoWhenBranchMatchedException();
                }
                this.n.invoke();
                Unit unit10 = Unit.a;
            }
        }
        return Unit.a;
    }
}
