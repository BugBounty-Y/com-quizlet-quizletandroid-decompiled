package com.quizlet.features.setpage.termlist.ads;

import androidx.glance.appwidget.protobuf.Z;
import com.google.android.gms.ads.admanager.AdManagerAdRequest;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;
import kotlinx.coroutines.C5028l;

/* loaded from: classes3.dex */
public final class d extends i implements Function2 {
    public int j;
    public final /* synthetic */ androidx.work.impl.model.i k;
    public final /* synthetic */ com.quizlet.ads.c l;
    public final /* synthetic */ AdManagerAdRequest m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(androidx.work.impl.model.i iVar, com.quizlet.ads.c cVar, AdManagerAdRequest adManagerAdRequest, h hVar) {
        super(2, hVar);
        this.k = iVar;
        this.l = cVar;
        this.m = adManagerAdRequest;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new d(this.k, this.l, this.m, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((d) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i != 0) {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
            return obj;
        }
        Z.e(obj);
        androidx.work.impl.model.i iVar = this.k;
        com.quizlet.ads.c cVar = this.l;
        AdManagerAdRequest adManagerAdRequest = this.m;
        this.j = 1;
        C5028l c5028l = new C5028l(1, kotlin.coroutines.intrinsics.h.b(this));
        c5028l.r();
        ((com.quizlet.ads.helper.b) iVar.d).b(cVar, new c(c5028l, 0), new c(c5028l, 1)).a().b(adManagerAdRequest);
        Object objQ = c5028l.q();
        if (objQ == aVar) {
            Intrinsics.checkNotNullParameter(this, "frame");
        }
        return objQ == aVar ? aVar : objQ;
    }
}
