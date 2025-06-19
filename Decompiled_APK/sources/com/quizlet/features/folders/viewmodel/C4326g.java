package com.quizlet.features.folders.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.eventlogger.EventLoggerExt;
import com.quizlet.features.folders.data.C4291k0;
import com.quizlet.features.folders.data.Q0;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: com.quizlet.features.folders.viewmodel.g, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4326g extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public N j;
    public int k;
    public final /* synthetic */ N l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4326g(N n, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = n;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C4326g(this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C4326g) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws Throwable {
        Object objF;
        N n;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.k;
        N n2 = this.l;
        long j = n2.r;
        if (i == 0) {
            Z.e(obj);
            this.j = n2;
            this.k = 1;
            objF = n2.d.f(j, this);
            if (objF == aVar) {
                return aVar;
            }
            n = n2;
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            n = this.j;
            Z.e(obj);
            objF = ((kotlin.r) obj).a;
        }
        kotlin.p pVar = kotlin.r.b;
        if (!(objF instanceof kotlin.q)) {
            Q0 q0G = n2.G();
            boolean z = q0G != null ? q0G.i : false;
            com.quizlet.features.folders.logging.e eVar = n2.h;
            eVar.getClass();
            EventLoggerExt.a(eVar.a, "folder_delete_confirmed", new com.quizlet.features.folders.logging.c(z, j, 0));
            n2.A.h(C4291k0.a);
        }
        n.N(objF, false);
        return Unit.a;
    }
}
