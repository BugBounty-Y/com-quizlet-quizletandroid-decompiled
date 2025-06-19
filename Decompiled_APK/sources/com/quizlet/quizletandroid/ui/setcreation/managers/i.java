package com.quizlet.quizletandroid.ui.setcreation.managers;

import android.os.Bundle;
import androidx.lifecycle.InterfaceC1250k;
import androidx.lifecycle.J;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.quizlet.db.data.models.base.DBModel;
import com.quizlet.db.data.models.persisted.DBStudySet;
import com.quizlet.db.data.models.persisted.DBTerm;
import com.quizlet.db.data.models.persisted.base.Models;
import com.quizlet.db.data.models.persisted.fields.DBStudySetFields;
import com.quizlet.db.data.models.persisted.fields.DBTermFields;
import com.quizlet.db.data.net.tasks.ExecutionRouter;
import com.quizlet.generated.enums.O1;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Objects;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class i implements InterfaceC1250k {
    public final com.quizlet.infra.legacysyncengine.datasources.d a;
    public final com.quizlet.infra.legacysyncengine.managers.i d;
    public final com.quizlet.quizletandroid.ui.setcreation.managers.interfaces.a e;
    public final p f;
    public final long g;
    public final boolean h;
    public final com.quizlet.db.b i;
    public final ExecutionRouter j;
    public Long k;
    public boolean l;
    public DBStudySet m;
    public com.quizlet.infra.legacysyncengine.datasources.o n;
    public WeakReference p;
    public com.quizlet.infra.legacysyncengine.datasources.o r;
    public boolean s = false;
    public ArrayList t = null;
    public final h b = new h(this, 0);
    public final h c = new h(this, 1);
    public io.reactivex.rxjava3.subjects.r o = new io.reactivex.rxjava3.subjects.r();
    public io.reactivex.rxjava3.subjects.r q = new io.reactivex.rxjava3.subjects.r();

    public i(com.quizlet.infra.legacysyncengine.datasources.d dVar, com.quizlet.infra.legacysyncengine.managers.i iVar, com.quizlet.quizletandroid.ui.setcreation.managers.interfaces.a aVar, p pVar, com.quizlet.db.b bVar, ExecutionRouter executionRouter, long j, boolean z) {
        this.a = dVar;
        this.d = iVar;
        this.e = aVar;
        this.f = pVar;
        this.g = j;
        this.h = z;
        this.i = bVar;
        this.j = executionRouter;
    }

    public final void a(int i, boolean z) {
        g gVar = (g) this.p.get();
        if (gVar == null) {
            return;
        }
        gVar.j(i, z);
    }

    public final boolean b(O1 termSide) {
        if (this.k.longValue() > 0) {
            return true;
        }
        long jLongValue = this.k.longValue();
        com.quizlet.db.b bVar = this.i;
        bVar.getClass();
        Intrinsics.checkNotNullParameter(termSide, "termSide");
        StringBuilder sb = new StringBuilder("setLanguage-");
        sb.append(jLongValue);
        sb.append("-");
        sb.append(termSide);
        return bVar.a.getBoolean(sb.toString(), false);
    }

    public final void c(Bundle bundle) {
        g gVar = (g) this.p.get();
        if (gVar == null) {
            return;
        }
        Bundle extras = gVar.getIntent().getExtras();
        if (bundle == null) {
            bundle = extras;
        }
        Long lValueOf = bundle == null ? null : Long.valueOf(bundle.getLong("editSetActivityId"));
        boolean z = false;
        if (bundle != null && bundle.getBoolean("editSetActivityIsCopySetFlow", false)) {
            z = true;
        }
        this.k = lValueOf;
        this.l = z;
        timber.log.c.a.a("(re)Starting the Edit Set Activity w/ Set Id : %d", lValueOf);
    }

    public final void e(com.quizlet.infra.legacysyncengine.net.f fVar) {
        DBStudySet dBStudySet = this.m;
        if (dBStudySet == null || !dBStudySet.getIsCreated()) {
            timber.log.c.a.a("Set has not been marked for creation, will not sync", new Object[0]);
            return;
        }
        timber.log.c.a.a("Syncing already-published-set with server", new Object[0]);
        com.jakewharton.rxbinding4.a aVarO = io.reactivex.rxjava3.core.i.o(Arrays.asList(Models.IMAGE, Models.TERM, Models.STUDY_SET));
        Objects.requireNonNull(fVar);
        aVarO.m(new com.quizlet.infra.legacysyncengine.net.d(fVar, 0), SubsamplingScaleImageView.TILE_SIZE_AUTO).t();
    }

    public final void f(final O1 o1, final String str, final boolean z) {
        this.o.i(new io.reactivex.rxjava3.functions.d() { // from class: com.quizlet.quizletandroid.ui.setcreation.managers.f
            @Override // io.reactivex.rxjava3.functions.d
            public final void accept(Object obj) {
                DBStudySet dBStudySet = (DBStudySet) obj;
                i iVar = this.a;
                iVar.getClass();
                O1 o12 = O1.WORD;
                O1 termSide = o1;
                String str2 = str;
                if (termSide == o12) {
                    dBStudySet.setWordLang(str2);
                } else if (termSide == O1.DEFINITION) {
                    dBStudySet.setDefLang(str2);
                }
                iVar.d.c(dBStudySet);
                if (z || iVar.b(termSide)) {
                    return;
                }
                long jLongValue = iVar.k.longValue();
                com.quizlet.db.b bVar = iVar.i;
                bVar.getClass();
                Intrinsics.checkNotNullParameter(termSide, "termSide");
                bVar.a.edit().putBoolean("setLanguage-" + jLongValue + "-" + termSide, true).apply();
            }
        }, new com.quizlet.billing.subscriptions.c(2));
    }

    public final void g(int i, ArrayList arrayList) {
        ArrayList arrayList2 = new ArrayList();
        while (i < arrayList.size()) {
            DBTerm dBTerm = (DBTerm) arrayList.get(i);
            if (dBTerm.getRank() != i) {
                dBTerm.setRank(i);
                arrayList2.add(dBTerm);
            }
            i++;
        }
        com.quizlet.infra.legacysyncengine.managers.i iVar = this.d;
        iVar.a(arrayList2, null);
        DBStudySet dBStudySet = this.m;
        if (dBStudySet != null && dBStudySet.getNumTerms() != arrayList.size()) {
            this.m.setNumTerms(arrayList.size());
            iVar.c(this.m);
        }
        this.e.a = false;
    }

    @Override // androidx.lifecycle.InterfaceC1250k
    public final void onCreate(J j) {
        Long l = this.k;
        this.s = l == null || l.longValue() <= 0;
        Long l2 = this.k;
        com.quizlet.quizletandroid.ui.setcreation.managers.interfaces.a aVar = this.e;
        if (l2 == null || l2.longValue() == 0) {
            DBStudySet dBStudySet = new DBStudySet();
            this.m = dBStudySet;
            dBStudySet.setDeleted(false);
            this.m.setCreatorId(this.g);
            int size = 2;
            this.m.setAccessType(this.h ? 2 : 0);
            this.m.setHasImages(Boolean.FALSE);
            DBStudySet dBStudySet2 = this.m;
            ArrayList arrayList = this.t;
            if (arrayList != null && !arrayList.isEmpty()) {
                size = this.t.size();
            }
            dBStudySet2.setNumTerms(size);
            DBModel[] dBModelArr = {this.m};
            com.quizlet.infra.legacysyncengine.managers.i iVar = this.d;
            iVar.c(dBModelArr);
            this.k = Long.valueOf(this.m.getId());
            ArrayList arrayList2 = this.t;
            if (arrayList2 == null || arrayList2.isEmpty()) {
                DBTerm dBTerm = new DBTerm();
                DBTerm dBTerm2 = new DBTerm();
                dBTerm.setSetId(this.m.getId());
                dBTerm.setRank(0);
                dBTerm2.setSetId(this.m.getSetId());
                dBTerm2.setRank(1);
                iVar.c(dBTerm);
                iVar.c(dBTerm2);
            } else {
                f(O1.WORD, "en", false);
                f(O1.DEFINITION, "en", false);
                if (this.t.size() > 0) {
                    DBTerm dBTerm3 = new DBTerm();
                    dBTerm3.setSetId(this.m.getId());
                    dBTerm3.setRank(0);
                    this.t.get(0).getClass();
                    throw new ClassCastException();
                }
            }
            aVar.a = true;
        } else {
            aVar.a = false;
        }
        Long l3 = this.k;
        l3.getClass();
        com.quizlet.infra.legacysyncengine.datasources.d dVar = this.a;
        com.quizlet.infra.legacysyncengine.orm.b bVar = new com.quizlet.infra.legacysyncengine.orm.b(Models.STUDY_SET);
        bVar.b(l3, DBStudySetFields.ID);
        com.quizlet.infra.legacysyncengine.orm.query.a aVarA = bVar.a();
        com.quizlet.infra.legacysyncengine.net.c cVar = dVar.a;
        this.n = new com.quizlet.infra.legacysyncengine.datasources.o(cVar, aVarA);
        Long l4 = this.k;
        l4.getClass();
        com.quizlet.infra.legacysyncengine.orm.b bVar2 = new com.quizlet.infra.legacysyncengine.orm.b(Models.TERM);
        bVar2.b(l4, DBTermFields.SET);
        this.r = new com.quizlet.infra.legacysyncengine.datasources.o(cVar, bVar2.a());
    }

    @Override // androidx.lifecycle.InterfaceC1250k
    public final void onPause(J j) {
        this.n.a(this.b);
        this.r.a(this.c);
    }

    @Override // androidx.lifecycle.InterfaceC1250k
    public final void onResume(J j) {
        this.n.e(this.b);
        this.r.e(this.c);
        this.n.d();
        this.r.d();
    }

    @Override // androidx.lifecycle.InterfaceC1250k
    public final void onStart(J j) {
        if (this.o.s() || this.o.r()) {
            this.o = new io.reactivex.rxjava3.subjects.r();
        }
        if (this.q.s() || this.q.r()) {
            this.q = new io.reactivex.rxjava3.subjects.r();
        }
    }
}
