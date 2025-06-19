package com.quizlet.infra.legacysyncengine.datasources;

import com.quizlet.db.data.models.persisted.DBStudySet;
import com.quizlet.db.data.models.persisted.DBUser;
import com.quizlet.db.data.models.persisted.base.Models;
import com.quizlet.db.data.models.persisted.fields.DBStudySetFields;
import com.quizlet.db.data.orm.Relationship;
import io.reactivex.rxjava3.internal.operators.observable.J;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/* loaded from: classes3.dex */
public final class h extends c {
    public final io.reactivex.rxjava3.subjects.d b;
    public final com.quizlet.infra.legacysyncengine.net.c c;
    public Set d;
    public final com.quizlet.infra.legacysyncengine.orm.query.a e;
    public final f f;
    public final J g;
    public io.reactivex.rxjava3.internal.observers.h h;

    public h(com.quizlet.infra.legacysyncengine.net.c cVar, Long l) {
        io.reactivex.rxjava3.subjects.d dVarZ = io.reactivex.rxjava3.subjects.d.z();
        this.b = dVarZ;
        this.c = cVar;
        com.quizlet.infra.legacysyncengine.orm.b bVar = new com.quizlet.infra.legacysyncengine.orm.b(Models.STUDY_SET);
        Relationship<DBStudySet, DBUser> relationship = DBStudySetFields.CREATOR;
        bVar.b(l, relationship);
        bVar.e(relationship);
        this.e = bVar.a();
        this.f = new f(this, 0);
        this.g = dVarZ.q(new e(this, 1));
    }

    @Override // com.quizlet.infra.legacysyncengine.datasources.c
    public final void a(b bVar) {
        ConcurrentHashMap.KeySetView keySetView = this.a;
        if (keySetView.remove(bVar) && keySetView.size() == 0) {
            io.reactivex.rxjava3.internal.observers.h hVar = this.h;
            if (hVar != null) {
                io.reactivex.rxjava3.internal.disposables.a.a(hVar);
                this.h = null;
            }
            this.c.a(this.e, this.f);
        }
    }

    @Override // com.quizlet.infra.legacysyncengine.datasources.c
    public final List b() {
        return this.d == null ? Collections.EMPTY_LIST : new ArrayList(this.d);
    }

    @Override // com.quizlet.infra.legacysyncengine.datasources.c
    public final io.reactivex.rxjava3.core.i d() {
        return new io.reactivex.rxjava3.internal.operators.mixed.b(1, new J(this.c.b(this.e, com.quizlet.infra.legacysyncengine.net.b.a).m(), new com.quizlet.baserecyclerview.decoration.a(11), 2).l(new com.quizlet.baserecyclerview.decoration.a(12)).q(new com.quizlet.baserecyclerview.decoration.a(13)).x(16).g(new com.quizlet.baserecyclerview.decoration.a(14)), new e(this, 0));
    }

    @Override // com.quizlet.infra.legacysyncengine.datasources.c
    public final boolean e(b bVar) {
        boolean zE = super.e(bVar);
        if (zE && this.a.size() == 1) {
            this.c.e(this.e, this.f);
            this.h = (io.reactivex.rxjava3.internal.observers.h) this.g.u(new com.quizlet.billing.subscriptions.a(this, 5), new com.quizlet.billing.subscriptions.c(3), io.reactivex.rxjava3.internal.functions.d.c);
        }
        return zE;
    }
}
