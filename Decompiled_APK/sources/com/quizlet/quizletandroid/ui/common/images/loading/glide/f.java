package com.quizlet.quizletandroid.ui.common.images.loading.glide;

import com.bumptech.glide.g;
import io.reactivex.rxjava3.core.o;
import io.reactivex.rxjava3.internal.operators.completable.l;
import io.reactivex.rxjava3.internal.operators.maybe.j;
import io.reactivex.rxjava3.internal.operators.maybe.r;
import io.reactivex.rxjava3.internal.operators.maybe.u;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Objects;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class f implements com.bumptech.glide.load.data.e {
    public final com.quizlet.quizletandroid.ui.common.images.loading.offline.a a;
    public final com.quizlet.quizletandroid.ui.common.images.loading.offline.c b;
    public FileInputStream c;
    public final boolean d;

    public f(com.quizlet.quizletandroid.ui.common.images.loading.offline.a payload, com.quizlet.quizletandroid.ui.common.images.loading.offline.c persistentImageResourceStore) {
        Intrinsics.checkNotNullParameter(payload, "payload");
        Intrinsics.checkNotNullParameter(persistentImageResourceStore, "persistentImageResourceStore");
        this.a = payload;
        this.b = persistentImageResourceStore;
        String url = payload.a;
        persistentImageResourceStore.getClass();
        Intrinsics.checkNotNullParameter(url, "url");
        File fileB = persistentImageResourceStore.b.b(url);
        Intrinsics.checkNotNullExpressionValue(fileB, "get(...)");
        this.d = fileB.exists();
    }

    @Override // com.bumptech.glide.load.data.e
    public final void cancel() throws IOException {
        FileInputStream fileInputStream = this.c;
        if (fileInputStream != null) {
            fileInputStream.close();
        }
    }

    @Override // com.bumptech.glide.load.data.e
    public final void f() throws IOException {
        FileInputStream fileInputStream = this.c;
        if (fileInputStream != null) {
            fileInputStream.close();
        }
    }

    @Override // com.bumptech.glide.load.data.e
    public final int g() {
        return this.d ? 3 : 2;
    }

    @Override // com.bumptech.glide.load.data.e
    public final Class getDataClass() {
        return InputStream.class;
    }

    @Override // com.bumptech.glide.load.data.e
    public final void h(g priority, com.bumptech.glide.load.data.d callback) {
        Intrinsics.checkNotNullParameter(priority, "priority");
        Intrinsics.checkNotNullParameter(callback, "callback");
        com.quizlet.quizletandroid.ui.common.images.loading.offline.c cVar = this.b;
        cVar.getClass();
        com.quizlet.quizletandroid.ui.common.images.loading.offline.a imagePayload = this.a;
        Intrinsics.checkNotNullParameter(imagePayload, "imagePayload");
        io.reactivex.rxjava3.core.g gVarA = cVar.a(imagePayload.f);
        o oVar = io.reactivex.rxjava3.schedulers.e.c;
        Objects.requireNonNull(oVar, "scheduler is null");
        j jVar = new j(new r(gVarA, oVar, 1), d.a, 1);
        com.quizlet.analytics.marketing.e eVar = new com.quizlet.analytics.marketing.e(this, 26);
        com.quizlet.infra.legacysyncengine.net.request.g gVar = io.reactivex.rxjava3.internal.functions.d.d;
        new u(jVar, gVar, eVar, gVar, io.reactivex.rxjava3.internal.functions.d.c).e(new l(new e(callback, 0), new e(callback, 1), new com.quizlet.eventlogger.e(callback, 18)));
    }
}
