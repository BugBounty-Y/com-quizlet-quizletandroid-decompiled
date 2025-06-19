package com.quizlet.infra.legacysyncengine.datasources;

import com.quizlet.db.data.models.persisted.DBFolder;
import com.quizlet.db.data.models.persisted.DBUser;
import com.quizlet.db.data.models.persisted.base.Models;
import com.quizlet.db.data.models.persisted.fields.DBBookmarkFields;
import com.quizlet.db.data.models.persisted.fields.DBFolderFields;
import com.quizlet.db.data.orm.Relationship;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;
import kotlin.collections.K;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class n extends c {
    public final com.quizlet.infra.legacysyncengine.net.c b;
    public final io.reactivex.rxjava3.core.i c;
    public final io.reactivex.rxjava3.subjects.d d;
    public final io.reactivex.rxjava3.subjects.d e;
    public final com.quizlet.infra.legacysyncengine.orm.query.a f;
    public final com.quizlet.infra.legacysyncengine.orm.query.a g;
    public List h;
    public final i i;
    public final i j;
    public AtomicReference k;

    public n(long j, com.quizlet.infra.legacysyncengine.net.c loader) {
        Intrinsics.checkNotNullParameter(loader, "loader");
        this.b = loader;
        io.reactivex.rxjava3.subjects.d dVarZ = io.reactivex.rxjava3.subjects.d.z();
        Intrinsics.checkNotNullExpressionValue(dVarZ, "create(...)");
        this.d = dVarZ;
        io.reactivex.rxjava3.subjects.d dVarZ2 = io.reactivex.rxjava3.subjects.d.z();
        Intrinsics.checkNotNullExpressionValue(dVarZ2, "create(...)");
        this.e = dVarZ2;
        com.quizlet.infra.legacysyncengine.orm.b bVar = new com.quizlet.infra.legacysyncengine.orm.b(Models.FOLDER);
        Relationship<DBFolder, DBUser> relationship = DBFolderFields.PERSON;
        bVar.b(Long.valueOf(j), relationship);
        bVar.e(relationship);
        com.quizlet.infra.legacysyncengine.orm.query.a aVarA = bVar.a();
        Intrinsics.checkNotNullExpressionValue(aVarA, "build(...)");
        this.f = aVarA;
        com.quizlet.infra.legacysyncengine.orm.b bVar2 = new com.quizlet.infra.legacysyncengine.orm.b(Models.BOOKMARK);
        bVar2.b(Long.valueOf(j), DBBookmarkFields.PERSON);
        bVar2.e(DBBookmarkFields.FOLDER, relationship);
        com.quizlet.infra.legacysyncengine.orm.query.a aVarA2 = bVar2.a();
        Intrinsics.checkNotNullExpressionValue(aVarA2, "build(...)");
        this.g = aVarA2;
        this.h = K.a;
        this.i = new i(this, 0);
        this.j = new i(this, 1);
        io.reactivex.rxjava3.disposables.d dVar = new io.reactivex.rxjava3.disposables.d(io.reactivex.rxjava3.internal.functions.d.b, 0);
        Intrinsics.checkNotNullExpressionValue(dVar, "empty(...)");
        this.k = dVar;
        io.reactivex.rxjava3.core.i iVarD = io.reactivex.rxjava3.core.i.d(dVarZ, dVarZ2, new com.lyft.android.scissors.b(this, 20));
        Intrinsics.checkNotNullExpressionValue(iVarD, "Observable.combineLatest…ombineFunction(t1, t2) })");
        this.c = iVarD;
    }

    /* JADX WARN: Type inference failed for: r4v3, types: [io.reactivex.rxjava3.disposables.b, java.util.concurrent.atomic.AtomicReference] */
    @Override // com.quizlet.infra.legacysyncengine.datasources.c
    public final void a(b listener) {
        Intrinsics.checkNotNullParameter(listener, "listener");
        ConcurrentHashMap.KeySetView keySetView = this.a;
        if (keySetView.remove(listener) && keySetView.size() == 0) {
            this.k.dispose();
            j jVar = new j(this.i, 0);
            com.quizlet.infra.legacysyncengine.orm.query.a aVar = this.f;
            com.quizlet.infra.legacysyncengine.net.c cVar = this.b;
            cVar.a(aVar, jVar);
            cVar.a(this.g, new k(this.j, 0));
        }
    }

    @Override // com.quizlet.infra.legacysyncengine.datasources.c
    public final List b() {
        return this.h;
    }

    @Override // com.quizlet.infra.legacysyncengine.datasources.c
    public final io.reactivex.rxjava3.core.i d() {
        Set set = com.quizlet.infra.legacysyncengine.net.c.e;
        com.quizlet.infra.legacysyncengine.orm.query.a aVar = this.g;
        com.quizlet.infra.legacysyncengine.net.c cVar = this.b;
        io.reactivex.rxjava3.subjects.p pVarC = cVar.c(aVar, set);
        Intrinsics.checkNotNullExpressionValue(pVarC, "get(...)");
        io.reactivex.rxjava3.subjects.p pVarC2 = cVar.c(this.f, set);
        Intrinsics.checkNotNullExpressionValue(pVarC2, "get(...)");
        io.reactivex.rxjava3.core.i iVarD = io.reactivex.rxjava3.core.i.d(pVarC, pVarC2, new r(4));
        Intrinsics.checkNotNullExpressionValue(iVarD, "Observable.combineLatest…ombineFunction(t1, t2) })");
        return iVarD;
    }

    @Override // com.quizlet.infra.legacysyncengine.datasources.c
    public final boolean e(b bVar) {
        boolean zE = super.e(bVar);
        if (zE && this.a.size() == 1) {
            this.k = (AtomicReference) this.c.u(new com.quizlet.analytics.marketing.e(this, 12), m.a, io.reactivex.rxjava3.internal.functions.d.c);
            j jVar = new j(this.i, 1);
            com.quizlet.infra.legacysyncengine.orm.query.a aVar = this.f;
            com.quizlet.infra.legacysyncengine.net.c cVar = this.b;
            cVar.e(aVar, jVar);
            cVar.e(this.g, new k(this.j, 1));
        }
        return zE;
    }
}
