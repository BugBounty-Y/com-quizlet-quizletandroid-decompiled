package androidx.work.impl.utils;

import android.content.Context;
import androidx.glance.appwidget.protobuf.Z;
import androidx.work.C1442p;
import androidx.work.impl.G;
import androidx.work.y;
import androidx.work.z;
import com.google.android.gms.internal.mlkit_vision_barcode.Z5;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3394t2;
import java.util.UUID;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;

/* loaded from: classes.dex */
public final class m extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ y k;
    public final /* synthetic */ androidx.work.impl.model.q l;
    public final /* synthetic */ p m;
    public final /* synthetic */ Context n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public m(y yVar, androidx.work.impl.model.q qVar, p pVar, Context context, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = yVar;
        this.l = qVar;
        this.m = pVar;
        this.n = context;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new m(this.k, this.l, this.m, this.n, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((m) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        y yVar = this.k;
        if (i == 0) {
            Z.e(obj);
            com.google.common.util.concurrent.e foregroundInfoAsync = yVar.getForegroundInfoAsync();
            Intrinsics.checkNotNullExpressionValue(foregroundInfoAsync, "worker.getForegroundInfoAsync()");
            this.j = 1;
            obj = G.a(foregroundInfoAsync, yVar, this);
            if (obj != aVar) {
            }
        }
        if (i != 1) {
            if (i != 2) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
            return obj;
        }
        Z.e(obj);
        C1442p c1442p = (C1442p) obj;
        androidx.work.impl.model.q qVar = this.l;
        if (c1442p == null) {
            throw new IllegalStateException(android.support.v4.media.session.a.t(new StringBuilder("Worker was marked important ("), qVar.c, ") but did not provide ForegroundInfo"));
        }
        int i2 = n.a;
        z.c().getClass();
        UUID id = yVar.getId();
        p pVar = this.m;
        androidx.concurrent.futures.l lVarH = AbstractC3394t2.h(pVar.a.a, "setForegroundAsync", new o(pVar, id, c1442p, this.n, 0));
        Intrinsics.checkNotNullExpressionValue(lVarH, "foregroundUpdater.setFor…orker.id, foregroundInfo)");
        this.j = 2;
        Object objC = Z5.c(lVarH, this);
        return objC == aVar ? aVar : objC;
    }
}
