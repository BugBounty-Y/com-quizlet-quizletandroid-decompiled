package com.quizlet.quizletandroid.ui.common.images.loading.offline;

import com.quizlet.infra.legacysyncengine.net.request.g;
import io.reactivex.rxjava3.core.o;
import io.reactivex.rxjava3.internal.functions.d;
import io.reactivex.rxjava3.internal.operators.maybe.f;
import io.reactivex.rxjava3.internal.operators.maybe.h;
import io.reactivex.rxjava3.internal.operators.maybe.j;
import io.reactivex.rxjava3.internal.operators.maybe.r;
import io.reactivex.rxjava3.internal.operators.maybe.s;
import io.reactivex.rxjava3.internal.operators.maybe.u;
import io.reactivex.rxjava3.internal.operators.single.k;
import io.reactivex.rxjava3.schedulers.e;
import java.io.File;
import java.util.Objects;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;
import okhttp3.A;

/* loaded from: classes3.dex */
public final class c implements com.quizlet.offline.data.a {
    public final A a;
    public final com.quizlet.quizletandroid.data.cache.a b;
    public final com.quizlet.quizletandroid.data.cache.c c;

    public c(A okHttpClient, com.quizlet.quizletandroid.data.cache.a persistentStorage, com.quizlet.quizletandroid.data.cache.c oldPersistentStorage) {
        Intrinsics.checkNotNullParameter(okHttpClient, "okHttpClient");
        Intrinsics.checkNotNullParameter(persistentStorage, "persistentStorage");
        Intrinsics.checkNotNullParameter(oldPersistentStorage, "oldPersistentStorage");
        this.a = okHttpClient;
        this.b = persistentStorage;
        this.c = oldPersistentStorage;
    }

    public static final j c(c cVar, String str, File file, com.quizlet.quizletandroid.data.cache.a aVar) {
        h hVarC = new com.quizlet.data.interactor.course.a(cVar.a).c(file, str);
        o oVar = e.c;
        Objects.requireNonNull(oVar, "scheduler is null");
        r rVar = new r(hVarC, oVar, 0);
        com.quizlet.quizletandroid.managers.audio.e eVar = new com.quizlet.quizletandroid.managers.audio.e(file, 1);
        g gVar = d.d;
        j jVar = new j(new s(new u(new u(rVar, gVar, gVar, eVar, d.c), gVar, gVar, gVar, new com.quizlet.quizletandroid.managers.audio.d(aVar, str, file, 1)), b.b, 0), b.c, 0);
        Intrinsics.checkNotNullExpressionValue(jVar, "flatMap(...)");
        return jVar;
    }

    @Override // com.quizlet.offline.data.a
    public final io.reactivex.rxjava3.core.g a(com.quizlet.qutils.data.offline.d payload) {
        Intrinsics.checkNotNullParameter(payload, "payload");
        String str = (String) payload.a;
        com.quizlet.quizletandroid.data.cache.a aVar = this.b;
        io.reactivex.rxjava3.internal.operators.flowable.b bVar = new io.reactivex.rxjava3.internal.operators.flowable.b(new com.quizlet.data.repository.folderwithcreator.a(this, str, aVar, 3), 4);
        Intrinsics.checkNotNullExpressionValue(bVar, "defer(...)");
        k kVarL = bVar.l(e.c);
        Intrinsics.checkNotNullExpressionValue(kVarL, "subscribeOn(...)");
        int iOrdinal = payload.e.ordinal();
        if (iOrdinal == 0) {
            h hVar = new h(3, kVarL, new com.quizlet.data.repository.folderset.c(this, str, aVar, 15));
            Intrinsics.checkNotNullExpressionValue(hVar, "flatMapMaybe(...)");
            return hVar;
        }
        if (iOrdinal == 1) {
            h hVar2 = new h(3, kVarL, new com.quizlet.data.repository.folderwithcreator.e(this, str, aVar, 15));
            Intrinsics.checkNotNullExpressionValue(hVar2, "flatMapMaybe(...)");
            return hVar2;
        }
        if (iOrdinal == 2) {
            f fVar = f.a;
            Intrinsics.checkNotNullExpressionValue(fVar, "empty(...)");
            return fVar;
        }
        if (iOrdinal != 3) {
            throw new NoWhenBranchMatchedException();
        }
        h hVar3 = new h(3, kVarL, b.d);
        Intrinsics.checkNotNullExpressionValue(hVar3, "flatMapMaybe(...)");
        return hVar3;
    }

    @Override // com.quizlet.offline.data.a
    public final io.reactivex.rxjava3.internal.operators.completable.h b(com.quizlet.qutils.data.offline.d payload) {
        Intrinsics.checkNotNullParameter(payload, "payload");
        io.reactivex.rxjava3.internal.operators.completable.h hVarH = new io.reactivex.rxjava3.internal.operators.completable.c(new com.quizlet.data.repository.classfolder.b(9, this, payload), 2).h(e.c);
        Intrinsics.checkNotNullExpressionValue(hVarH, "subscribeOn(...)");
        return hVarH;
    }
}
