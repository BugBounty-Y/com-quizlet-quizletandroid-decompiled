package com.quizlet.features.infra.folder.create.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.data.connectivity.NetworkOfflineError;
import com.quizlet.data.model.AbstractC4119d0;
import com.quizlet.features.infra.folder.create.data.d;
import com.quizlet.features.infra.folder.create.data.f;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.p;
import kotlin.q;
import kotlin.r;
import kotlinx.coroutines.C;
import kotlinx.coroutines.flow.s0;
import timber.log.c;

/* loaded from: classes3.dex */
public final class a extends i implements Function2 {
    public int j;
    public final /* synthetic */ b k;
    public final /* synthetic */ String l;
    public final /* synthetic */ String m;
    public final /* synthetic */ long n;
    public final /* synthetic */ long o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(b bVar, String str, String str2, long j, long j2, h hVar) {
        super(2, hVar);
        this.k = bVar;
        this.l = str;
        this.m = str2;
        this.n = j;
        this.o = j2;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new a(this.k, this.l, this.m, this.n, this.o, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((a) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        Object objF;
        Object value;
        Object cVar;
        Object value2;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        b bVar = this.k;
        if (i == 0) {
            Z.e(obj);
            this.j = 1;
            objF = bVar.b.f(this.l, this.m, this.n, this.o, this);
            if (objF == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
            objF = ((r) obj).a;
        }
        p pVar = r.b;
        boolean z = objF instanceof q;
        s0 s0Var = bVar.d;
        if (!z) {
            AbstractC4119d0 abstractC4119d0 = (AbstractC4119d0) objF;
            do {
                value2 = s0Var.getValue();
            } while (!s0Var.k(value2, new f(abstractC4119d0)));
            bVar.c.I("create_folder");
        }
        Throwable thA = r.a(objF);
        if (thA != null) {
            c.a.q(thA, "Encountered error saving a new Folder", new Object[0]);
            do {
                value = s0Var.getValue();
                if (thA instanceof NetworkOfflineError) {
                    com.quizlet.features.infra.folder.create.data.a errorType = com.quizlet.features.infra.folder.create.data.a.a;
                    Intrinsics.checkNotNullParameter(errorType, "errorType");
                    cVar = new com.quizlet.features.infra.folder.create.data.c();
                } else {
                    cVar = d.a;
                }
            } while (!s0Var.k(value, cVar));
        }
        return Unit.a;
    }
}
