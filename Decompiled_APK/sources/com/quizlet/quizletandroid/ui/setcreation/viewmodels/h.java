package com.quizlet.quizletandroid.ui.setcreation.viewmodels;

import android.net.Uri;
import androidx.lifecycle.X;
import androidx.lifecycle.Y;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.google.android.gms.internal.ads.Zh;
import com.quizlet.data.interactor.folderwithcreator.m;
import com.quizlet.db.data.models.persisted.DBStudySet;
import com.quizlet.db.data.models.persisted.DBTerm;
import com.quizlet.infra.legacysyncengine.managers.i;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.setcreation.managers.l;
import com.quizlet.scandocument.model.k;
import com.quizlet.scandocument.model.n;
import com.quizlet.scandocument.model.o;
import com.quizlet.scandocument.model.q;
import com.quizlet.scandocument.model.s;
import com.quizlet.scandocument.model.t;
import com.quizlet.scandocument.model.u;
import com.quizlet.scandocument.model.x;
import com.quizlet.scandocument.model.z;
import io.reactivex.rxjava3.internal.operators.observable.m0;
import io.reactivex.rxjava3.subjects.r;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.TreeSet;
import kotlin.Metadata;
import kotlin.collections.B;
import kotlin.collections.C;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt__StringsKt;

@Metadata
/* loaded from: classes3.dex */
public final class h extends com.quizlet.viewmodel.b {
    public final Zh c;
    public final m d;
    public final com.quizlet.scandocument.a e;
    public final com.quizlet.quizletandroid.ui.setcreation.tracking.c f;
    public final Y g;
    public final Y h;
    public final X i;
    public final Y j;
    public final Y k;
    public final Y l;
    public final Y m;
    public int n;
    public final ArrayList o;
    public com.quizlet.scandocument.model.h p;
    public q q;

    public h(Zh modelsManager, m ocrService, com.quizlet.scandocument.a intersectionService, com.quizlet.quizletandroid.ui.setcreation.tracking.c eventLogger) {
        Intrinsics.checkNotNullParameter(modelsManager, "modelsManager");
        Intrinsics.checkNotNullParameter(ocrService, "ocrService");
        Intrinsics.checkNotNullParameter(intersectionService, "intersectionService");
        Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
        this.c = modelsManager;
        this.d = ocrService;
        this.e = intersectionService;
        this.f = eventLogger;
        Y y = new Y();
        this.g = y;
        this.h = new Y();
        this.i = new X(1);
        this.j = new Y();
        this.k = new Y();
        this.l = new Y();
        this.m = new Y();
        this.o = new ArrayList();
        o oVar = o.a;
        this.q = oVar;
        y.j(oVar);
    }

    public final void B() {
        Object next;
        Zh zh = this.c;
        if (zh.b()) {
            Iterator it2 = ((List) zh.n).iterator();
            while (true) {
                if (!it2.hasNext()) {
                    next = null;
                    break;
                } else {
                    next = it2.next();
                    if (((DBTerm) next).isIncomplete()) {
                        break;
                    }
                }
            }
            DBTerm dBTerm = (DBTerm) next;
            if (dBTerm != null) {
                dBTerm.setDeleted(true);
                ((i) zh.f).c(dBTerm);
            }
        }
    }

    /* JADX WARN: Type inference failed for: r0v4, types: [java.lang.Iterable, java.lang.Object] */
    public final ArrayList C() {
        com.quizlet.scandocument.model.h hVar = this.p;
        if (hVar == null) {
            Intrinsics.m("ocrDocument");
            throw null;
        }
        ?? r0 = hVar.b.b;
        ArrayList arrayList = new ArrayList(C.q(r0, 10));
        Iterator it2 = r0.iterator();
        while (it2.hasNext()) {
            arrayList.add(((com.quizlet.scandocument.model.c) it2.next()).a);
        }
        return arrayList;
    }

    public final DBStudySet D() {
        DBStudySet dBStudySet = (DBStudySet) this.c.i;
        if (dBStudySet == null) {
            throw new IllegalStateException("Trying to access Study Set before it was intialized!");
        }
        Intrinsics.d(dBStudySet);
        return dBStudySet;
    }

    public final void E(Uri photoPath) {
        Intrinsics.checkNotNullParameter(photoPath, "imagePath");
        n nVar = n.a;
        this.q = nVar;
        this.g.l(nVar);
        m mVar = this.d;
        mVar.getClass();
        Intrinsics.checkNotNullParameter(photoPath, "photoPath");
        m0 m0VarW = new com.jakewharton.rxbinding4.a(new com.quizlet.data.repository.classfolder.b(11, mVar, photoPath), 4).w((io.reactivex.rxjava3.core.o) mVar.e);
        Intrinsics.checkNotNullExpressionValue(m0VarW, "subscribeOn(...)");
        io.reactivex.rxjava3.disposables.b bVarU = m0VarW.u(new g(this, 3), new g(this, 4), io.reactivex.rxjava3.internal.functions.d.c);
        Intrinsics.checkNotNullExpressionValue(bVarU, "subscribe(...)");
        Intrinsics.checkNotNullParameter(bVarU, "<this>");
        A(bVarU);
    }

    public final void F(String str) {
        int i;
        boolean z;
        DBStudySet dBStudySet;
        int i2 = 3;
        int i3 = 2;
        int i4 = 1;
        Zh zh = this.c;
        if (str != null && (dBStudySet = (DBStudySet) zh.i) != null) {
            dBStudySet.setTitle(str);
            ((i) zh.f).c(dBStudySet);
            ((r) zh.o).m().u(new com.quizlet.quizletandroid.ui.setcreation.managers.m(zh, i2), io.reactivex.rxjava3.internal.functions.d.e, io.reactivex.rxjava3.internal.functions.d.c);
            ((com.quizlet.quizletandroid.ui.setcreation.managers.interfaces.a) zh.g).a = false;
            ((r) zh.o).onSuccess(dBStudySet);
        }
        DBStudySet dBStudySet2 = (DBStudySet) zh.i;
        io.reactivex.rxjava3.subjects.d dVar = (io.reactivex.rxjava3.subjects.d) zh.q;
        if (dBStudySet2 != null) {
            if (!dBStudySet2.getIsCreated()) {
                List list = (List) zh.n;
                if (list == null || !list.isEmpty()) {
                    Iterator it2 = list.iterator();
                    i = 0;
                    while (it2.hasNext()) {
                        if (((DBTerm) it2.next()).hasValidUserContent() && (i = i + 1) < 0) {
                            B.o();
                            throw null;
                        }
                    }
                } else {
                    i = 0;
                }
                if (i < 2) {
                    dVar.b(u.a);
                } else if (zh.b()) {
                    dVar.b(s.a);
                } else if (org.apache.commons.lang3.e.c(dBStudySet2.getWordLang()) && org.apache.commons.lang3.e.c(dBStudySet2.getDefLang())) {
                    dVar.b(new x(R.string.term_languages_cannot_be_empty_message));
                } else if (org.apache.commons.lang3.e.c(dBStudySet2.getWordLang())) {
                    dVar.b(new x(R.string.word_language_cannot_be_empty_message));
                } else if (org.apache.commons.lang3.e.c(dBStudySet2.getDefLang())) {
                    dVar.b(new x(R.string.definition_language_cannot_be_empty_message));
                } else if (org.apache.commons.lang3.e.c(dBStudySet2.getTitle())) {
                    dVar.b(z.a);
                }
                z = false;
            }
            z = true;
        } else {
            z = false;
        }
        if (z) {
            String title = D().getTitle();
            DBStudySet dBStudySet3 = (DBStudySet) zh.i;
            if (dBStudySet3 != null) {
                dBStudySet3.setTitle(title);
            }
            dVar.b(t.a);
            DBStudySet dBStudySet4 = (DBStudySet) zh.i;
            if (dBStudySet4 != null) {
                io.reactivex.rxjava3.core.i.p(dBStudySet4).q(new com.quizlet.quizletandroid.ui.setcreation.managers.n(zh, 0)).m(new com.quizlet.login.common.interactors.d(zh, 7), SubsamplingScaleImageView.TILE_SIZE_AUTO).m(new com.quizlet.quizletandroid.ui.common.ads.prebid.creators.c(zh, 3), SubsamplingScaleImageView.TILE_SIZE_AUTO).l(com.quizlet.quizletandroid.ui.setcreation.managers.o.a).x(16).e(new com.quizlet.quizletandroid.ui.login.h(zh, 2)).i(new com.quizlet.quizletandroid.ui.setcreation.managers.m(zh, i4), new com.quizlet.quizletandroid.ui.setcreation.managers.m(zh, i3));
            }
        }
    }

    public final void G() {
        Zh zh = this.c;
        if (((r) zh.o).s() || ((r) zh.o).r()) {
            zh.o = new r();
        }
        if (((r) zh.p).s() || ((r) zh.p).r()) {
            zh.p = new r();
        }
        com.quizlet.infra.legacysyncengine.datasources.c cVarA = zh.a();
        l lVar = (l) zh.l;
        if (lVar == null) {
            Intrinsics.m("studySetListener");
            throw null;
        }
        cVarA.e(lVar);
        com.quizlet.infra.legacysyncengine.datasources.o oVar = (com.quizlet.infra.legacysyncengine.datasources.o) zh.k;
        if (oVar == null) {
            Intrinsics.m("termDataSource");
            throw null;
        }
        l lVar2 = (l) zh.m;
        if (lVar2 == null) {
            Intrinsics.m("termsListener");
            throw null;
        }
        oVar.e(lVar2);
        zh.a().d();
        com.quizlet.infra.legacysyncengine.datasources.o oVar2 = (com.quizlet.infra.legacysyncengine.datasources.o) zh.k;
        if (oVar2 != null) {
            oVar2.d();
        } else {
            Intrinsics.m("termDataSource");
            throw null;
        }
    }

    public final void H(String term, String definition) {
        DBTerm dBTerm;
        List<DBTerm> list;
        Intrinsics.checkNotNullParameter(term, "term");
        Intrinsics.checkNotNullParameter(definition, "definition");
        Integer num = (Integer) this.l.d();
        int iIntValue = (num != null ? num.intValue() : 1) - 1;
        Zh zh = this.c;
        zh.getClass();
        Intrinsics.checkNotNullParameter(term, "newTerm");
        Intrinsics.checkNotNullParameter(definition, "newDefinition");
        if (((DBStudySet) zh.i) == null) {
            throw new IllegalStateException("Set has to be initialzied before adding a term");
        }
        Intrinsics.checkNotNullParameter(term, "term");
        Intrinsics.checkNotNullParameter(definition, "definition");
        if (((List) zh.n).isEmpty() || ((list = (List) zh.n) != null && list.isEmpty())) {
            dBTerm = new DBTerm();
            DBStudySet dBStudySet = (DBStudySet) zh.i;
            Intrinsics.d(dBStudySet);
            dBTerm.setSetId(dBStudySet.getSetId());
            dBTerm.setWord(term);
            dBTerm.setDefinition(definition);
            dBTerm.setRank(iIntValue);
        } else {
            for (DBTerm dBTerm2 : list) {
                if (Intrinsics.b(dBTerm2.getWord(), term) && Intrinsics.b(dBTerm2.getDefinition(), definition)) {
                    dBTerm = (DBTerm) CollectionsKt.U((List) zh.n);
                    dBTerm.setWord(term);
                    dBTerm.setDefinition(definition);
                    dBTerm.setRank(iIntValue);
                    break;
                }
            }
            dBTerm = new DBTerm();
            DBStudySet dBStudySet2 = (DBStudySet) zh.i;
            Intrinsics.d(dBStudySet2);
            dBTerm.setSetId(dBStudySet2.getSetId());
            dBTerm.setWord(term);
            dBTerm.setDefinition(definition);
            dBTerm.setRank(iIntValue);
        }
        ((i) zh.f).c(dBTerm);
        ((r) zh.o).m().u(new com.quizlet.quizletandroid.ui.setcreation.managers.m(zh, 3), io.reactivex.rxjava3.internal.functions.d.e, io.reactivex.rxjava3.internal.functions.d.c);
        ((com.quizlet.quizletandroid.ui.setcreation.managers.interfaces.a) zh.g).a = false;
    }

    public final void I(String currentFieldText) {
        Intrinsics.checkNotNullParameter(currentFieldText, "lastWord");
        if (this.q instanceof k) {
            Intrinsics.checkNotNullParameter(currentFieldText, "currentFieldText");
            int i = 0;
            List listSplit$default = StringsKt__StringsKt.split$default(currentFieldText, new String[]{" "}, false, 0, 6, null);
            TreeSet indexes = new TreeSet();
            Iterator it2 = C().iterator();
            while (it2.hasNext()) {
                Object next = it2.next();
                int i2 = i + 1;
                if (i < 0) {
                    B.p();
                    throw null;
                }
                if (listSplit$default.contains((String) next)) {
                    indexes.add(Integer.valueOf(i));
                }
                i = i2;
            }
            com.quizlet.scandocument.a aVar = this.e;
            aVar.getClass();
            Intrinsics.checkNotNullParameter(indexes, "indexes");
            TreeSet treeSet = aVar.b;
            treeSet.removeAll(indexes);
            Intrinsics.checkNotNullParameter(indexes, "indexes");
            aVar.c.removeAll(indexes);
            this.n = treeSet.size();
            this.n = aVar.b.size();
            aVar.b.clear();
        }
    }
}
