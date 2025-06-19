package com.quizlet.remote.model.folder;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.r;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class k extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ p l;
    public final /* synthetic */ long m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public k(p pVar, long j, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = pVar;
        this.m = j;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        k kVar = new k(this.l, this.m, hVar);
        kVar.k = obj;
        return kVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((k) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        Object objB;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        try {
            if (i == 0) {
                Z.e(obj);
                p pVar = this.l;
                long j = this.m;
                kotlin.p pVar2 = r.b;
                com.quizlet.login.authentication.login.a aVar2 = pVar.a;
                this.j = 1;
                obj = aVar2.g(j, this);
                if (obj == aVar) {
                    return aVar;
                }
            } else {
                if (i != 1) {
                    throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                }
                Z.e(obj);
            }
            objB = Boolean.valueOf(Intrinsics.b(((FolderCopyEligibilityResponse) obj).a, Boolean.TRUE));
            kotlin.p pVar3 = r.b;
        } catch (Throwable th) {
            kotlin.p pVar4 = r.b;
            objB = Z.b(th);
        }
        return new r(objB);
    }
}
