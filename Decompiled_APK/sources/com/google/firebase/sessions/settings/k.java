package com.google.firebase.sessions.settings;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;
import kotlinx.coroutines.flow.InterfaceC4992i;
import kotlinx.coroutines.flow.e0;

/* loaded from: classes2.dex */
public final class k extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public n j;
    public int k;
    public final /* synthetic */ n l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public k(n nVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = nVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new k(this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((k) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        n nVar;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.k;
        if (i == 0) {
            Z.e(obj);
            n nVar2 = this.l;
            InterfaceC4992i data = nVar2.a.getData();
            this.j = nVar2;
            this.k = 1;
            Object objP = e0.p(data, this);
            if (objP == aVar) {
                return aVar;
            }
            nVar = nVar2;
            obj = objP;
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            nVar = this.j;
            Z.e(obj);
        }
        n.a(nVar, ((androidx.datastore.preferences.core.b) obj).h());
        return Unit.a;
    }
}
