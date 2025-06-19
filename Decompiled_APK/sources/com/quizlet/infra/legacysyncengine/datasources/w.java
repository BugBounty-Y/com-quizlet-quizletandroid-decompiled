package com.quizlet.infra.legacysyncengine.datasources;

import androidx.collection.C0219q;
import com.quizlet.db.data.models.base.SortOption;
import com.quizlet.db.data.models.persisted.DBSelectedTerm;
import com.quizlet.db.data.models.persisted.DBStudySet;
import com.quizlet.db.data.models.persisted.DBTerm;
import com.quizlet.db.data.models.persisted.base.Models;
import com.quizlet.db.data.models.persisted.fields.DBSelectedTermFields;
import com.quizlet.db.data.models.persisted.fields.DBTermFields;
import com.quizlet.db.data.orm.Relationship;
import io.reactivex.rxjava3.internal.operators.observable.C4885d;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import kotlin.Pair;

/* loaded from: classes3.dex */
public final class w extends c {
    public final com.quizlet.infra.legacysyncengine.net.c b;
    public final com.quizlet.infra.legacysyncengine.orm.query.a c;
    public final com.quizlet.infra.legacysyncengine.orm.query.a d;
    public SortOption e;
    public boolean f;
    public final io.reactivex.rxjava3.subjects.d g;
    public final io.reactivex.rxjava3.internal.operators.completable.c h;
    public final u i;
    public final u j;

    /* JADX WARN: Type inference failed for: r0v0, types: [com.quizlet.infra.legacysyncengine.datasources.u] */
    /* JADX WARN: Type inference failed for: r0v1, types: [com.quizlet.infra.legacysyncengine.datasources.u] */
    public w(com.quizlet.infra.legacysyncengine.net.c cVar, long j, long j2, boolean z, SortOption sortOption) {
        final int i = 0;
        this.i = new com.quizlet.infra.legacysyncengine.a(this) { // from class: com.quizlet.infra.legacysyncengine.datasources.u
            public final /* synthetic */ w b;

            {
                this.b = this;
            }

            @Override // com.quizlet.infra.legacysyncengine.a
            public final void a(ArrayList arrayList) {
                switch (i) {
                    case 0:
                        this.b.c();
                        break;
                    default:
                        this.b.c();
                        break;
                }
            }
        };
        final int i2 = 1;
        this.j = new com.quizlet.infra.legacysyncengine.a(this) { // from class: com.quizlet.infra.legacysyncengine.datasources.u
            public final /* synthetic */ w b;

            {
                this.b = this;
            }

            @Override // com.quizlet.infra.legacysyncengine.a
            public final void a(ArrayList arrayList) {
                switch (i2) {
                    case 0:
                        this.b.c();
                        break;
                    default:
                        this.b.c();
                        break;
                }
            }
        };
        this.b = cVar;
        this.f = z;
        com.quizlet.infra.legacysyncengine.orm.b bVar = new com.quizlet.infra.legacysyncengine.orm.b(Models.TERM);
        Relationship<DBTerm, DBStudySet> relationship = DBTermFields.SET;
        bVar.b(Long.valueOf(j), relationship);
        bVar.e(relationship);
        com.quizlet.infra.legacysyncengine.orm.query.a aVarA = bVar.a();
        this.c = aVarA;
        com.quizlet.infra.legacysyncengine.orm.b bVar2 = new com.quizlet.infra.legacysyncengine.orm.b(Models.SELECTED_TERM);
        bVar2.b(Long.valueOf(j), DBSelectedTermFields.SET);
        bVar2.b(Long.valueOf(j2), DBSelectedTermFields.PERSON);
        this.d = bVar2.a();
        io.reactivex.rxjava3.subjects.d dVarZ = io.reactivex.rxjava3.subjects.d.z();
        this.g = dVarZ;
        this.h = new io.reactivex.rxjava3.internal.operators.completable.c(new io.reactivex.rxjava3.internal.operators.flowable.b(io.reactivex.rxjava3.core.g.d(new io.reactivex.rxjava3.internal.operators.maybe.h(0, new com.jakewharton.rxbinding4.a(new com.google.firebase.tracing.a(14, this, aVarA), 3).j().g(new com.quizlet.baserecyclerview.decoration.a(21)), new com.quizlet.baserecyclerview.decoration.a(22)), new io.reactivex.rxjava3.internal.operators.maybe.e(dVarZ.j(), 3)), 0), 6);
        this.e = sortOption;
    }

    @Override // com.quizlet.infra.legacysyncengine.datasources.c
    public final void a(b bVar) {
        ConcurrentHashMap.KeySetView keySetView = this.a;
        if (keySetView.remove(bVar) && keySetView.size() == 0) {
            u uVar = this.i;
            com.quizlet.infra.legacysyncengine.net.c cVar = this.b;
            cVar.a(this.c, uVar);
            cVar.a(this.d, this.j);
        }
    }

    @Override // com.quizlet.infra.legacysyncengine.datasources.c
    public final List b() {
        com.quizlet.infra.legacysyncengine.net.c cVar = this.b;
        ArrayList arrayListD = cVar.d(this.c);
        ArrayList arrayListD2 = cVar.d(this.d);
        if (arrayListD == null || arrayListD2 == null) {
            return null;
        }
        C4885d c4885dX = io.reactivex.rxjava3.core.i.o(arrayListD).x(16);
        io.reactivex.rxjava3.internal.operators.single.g gVarG = io.reactivex.rxjava3.core.i.o(arrayListD2).x(16).g(new com.quizlet.baserecyclerview.decoration.a(20));
        final boolean z = this.f;
        return (List) io.reactivex.rxjava3.core.p.p(c4885dX, gVarG, new io.reactivex.rxjava3.functions.b() { // from class: com.quizlet.infra.legacysyncengine.datasources.v
            @Override // io.reactivex.rxjava3.functions.b
            public final Object apply(Object obj, Object obj2) {
                C0219q c0219q = (C0219q) obj2;
                ArrayList arrayList = new ArrayList();
                for (DBTerm dBTerm : (List) obj) {
                    DBSelectedTerm dBSelectedTerm = (DBSelectedTerm) c0219q.c(dBTerm.getId());
                    if (!z || dBSelectedTerm != null) {
                        arrayList.add(new Pair(dBTerm, dBSelectedTerm));
                    }
                }
                return arrayList;
            }
        }).g(new com.google.android.material.search.a(this, 25)).b();
    }

    @Override // com.quizlet.infra.legacysyncengine.datasources.c
    public final io.reactivex.rxjava3.core.i d() {
        Set set = com.quizlet.infra.legacysyncengine.net.c.e;
        com.quizlet.infra.legacysyncengine.orm.query.a aVar = this.c;
        com.quizlet.infra.legacysyncengine.net.c cVar = this.b;
        io.reactivex.rxjava3.subjects.p pVarC = cVar.c(aVar, set);
        io.reactivex.rxjava3.subjects.p pVarC2 = cVar.c(this.d, set);
        pVarC.u(new t(this, 0), io.reactivex.rxjava3.internal.functions.d.e, io.reactivex.rxjava3.internal.functions.d.c);
        return new io.reactivex.rxjava3.internal.operators.maybe.h(2, io.reactivex.rxjava3.core.i.r(pVarC, pVarC2), new com.quizlet.baserecyclerview.decoration.a(19)).g();
    }

    @Override // com.quizlet.infra.legacysyncengine.datasources.c
    public final boolean e(b bVar) {
        boolean zE = super.e(bVar);
        if (zE && this.a.size() == 1) {
            u uVar = this.i;
            com.quizlet.infra.legacysyncengine.net.c cVar = this.b;
            cVar.e(this.c, uVar);
            cVar.e(this.d, this.j);
        }
        return zE;
    }
}
