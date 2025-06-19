package com.quizlet.quizletandroid.managers.audio;

import io.reactivex.rxjava3.core.o;
import io.reactivex.rxjava3.internal.operators.maybe.j;
import io.reactivex.rxjava3.internal.operators.maybe.r;
import io.reactivex.rxjava3.internal.operators.maybe.s;
import io.reactivex.rxjava3.internal.operators.maybe.u;
import io.reactivex.rxjava3.internal.operators.single.k;
import java.io.File;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;
import okhttp3.A;

/* loaded from: classes3.dex */
public final class g implements com.quizlet.offline.data.a {
    public final A a;
    public final com.quizlet.quizletandroid.data.cache.c b;
    public final com.quizlet.quizletandroid.data.cache.b c;
    public final o d;

    public g(A okHttpClient, com.quizlet.quizletandroid.data.cache.c persistentStorage, com.quizlet.quizletandroid.data.cache.b temporaryStorage, o ioScheduler) {
        Intrinsics.checkNotNullParameter(okHttpClient, "okHttpClient");
        Intrinsics.checkNotNullParameter(persistentStorage, "persistentStorage");
        Intrinsics.checkNotNullParameter(temporaryStorage, "temporaryStorage");
        Intrinsics.checkNotNullParameter(ioScheduler, "ioScheduler");
        this.a = okHttpClient;
        this.b = persistentStorage;
        this.c = temporaryStorage;
        this.d = ioScheduler;
    }

    public static final j c(g gVar, String str, File file, com.quizlet.quizletandroid.data.cache.a aVar) {
        r rVar = new r(new com.quizlet.data.interactor.course.a(gVar.a).c(file, str), gVar.d, 0);
        e eVar = new e(file, 0);
        com.quizlet.infra.legacysyncengine.net.request.g gVar2 = io.reactivex.rxjava3.internal.functions.d.d;
        s sVar = new s(new u(new u(rVar, gVar2, gVar2, eVar, io.reactivex.rxjava3.internal.functions.d.c), gVar2, gVar2, gVar2, new d(aVar, str, file, 0)), f.a, 0);
        com.google.android.gms.ads.nonagon.util.logging.csi.a aVar2 = new com.google.android.gms.ads.nonagon.util.logging.csi.a();
        aVar2.a = str;
        j jVar = new j(sVar, aVar2, 0);
        Intrinsics.checkNotNullExpressionValue(jVar, "flatMap(...)");
        return jVar;
    }

    @Override // com.quizlet.offline.data.a
    public final io.reactivex.rxjava3.core.g a(com.quizlet.qutils.data.offline.d payload) {
        Object obj;
        Intrinsics.checkNotNullParameter(payload, "payload");
        String str = (String) payload.a;
        int iOrdinal = payload.b.ordinal();
        if (iOrdinal == 0) {
            obj = this.b;
        } else {
            if (iOrdinal != 1) {
                throw new NoWhenBranchMatchedException();
            }
            obj = this.c;
        }
        io.reactivex.rxjava3.internal.operators.flowable.b bVar = new io.reactivex.rxjava3.internal.operators.flowable.b(new com.quizlet.data.repository.folderwithcreator.a(this, str, obj, 2), 4);
        Intrinsics.checkNotNullExpressionValue(bVar, "defer(...)");
        k kVarL = bVar.l(this.d);
        Intrinsics.checkNotNullExpressionValue(kVarL, "subscribeOn(...)");
        int iOrdinal2 = payload.e.ordinal();
        if (iOrdinal2 == 0) {
            io.reactivex.rxjava3.internal.operators.maybe.h hVar = new io.reactivex.rxjava3.internal.operators.maybe.h(3, kVarL, new com.google.android.gms.internal.appset.e(this, str, obj, 15));
            Intrinsics.checkNotNullExpressionValue(hVar, "flatMapMaybe(...)");
            return hVar;
        }
        if (iOrdinal2 == 1) {
            io.reactivex.rxjava3.internal.operators.maybe.h hVar2 = new io.reactivex.rxjava3.internal.operators.maybe.h(3, kVarL, new com.quizlet.data.interactor.set.c(str, this, obj));
            Intrinsics.checkNotNullExpressionValue(hVar2, "flatMapMaybe(...)");
            return hVar2;
        }
        if (iOrdinal2 == 2) {
            io.reactivex.rxjava3.internal.operators.maybe.f fVar = io.reactivex.rxjava3.internal.operators.maybe.f.a;
            Intrinsics.checkNotNullExpressionValue(fVar, "empty(...)");
            return fVar;
        }
        if (iOrdinal2 != 3) {
            throw new NoWhenBranchMatchedException();
        }
        io.reactivex.rxjava3.internal.operators.maybe.h hVar3 = new io.reactivex.rxjava3.internal.operators.maybe.h(3, kVarL, f.b);
        Intrinsics.checkNotNullExpressionValue(hVar3, "flatMapMaybe(...)");
        return hVar3;
    }

    @Override // com.quizlet.offline.data.a
    public final io.reactivex.rxjava3.internal.operators.completable.h b(com.quizlet.qutils.data.offline.d payload) {
        Intrinsics.checkNotNullParameter(payload, "payload");
        io.reactivex.rxjava3.internal.operators.completable.h hVarH = new io.reactivex.rxjava3.internal.operators.completable.c(new androidx.work.impl.A(11, this, payload), 4).h(this.d);
        Intrinsics.checkNotNullExpressionValue(hVarH, "subscribeOn(...)");
        return hVarH;
    }
}
