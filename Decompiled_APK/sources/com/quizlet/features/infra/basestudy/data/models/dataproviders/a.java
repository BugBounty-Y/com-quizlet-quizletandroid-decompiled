package com.quizlet.features.infra.basestudy.data.models.dataproviders;

import androidx.collection.C0219q;
import androidx.compose.runtime.changelist.K;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.google.android.gms.internal.mlkit_vision_barcode.x7;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3537t4;
import com.quizlet.db.data.models.identity.ModelIdentityProvider;
import com.quizlet.db.data.models.interfaces.StudyableModel;
import com.quizlet.db.data.models.persisted.DBSession;
import com.quizlet.db.data.models.persisted.DBStudySet;
import com.quizlet.db.data.models.persisted.DBTerm;
import com.quizlet.db.data.models.persisted.base.ModelType;
import com.quizlet.db.data.models.persisted.base.Models;
import com.quizlet.db.data.models.persisted.fields.DBDiagramShapeFields;
import com.quizlet.db.data.models.persisted.fields.DBImageRefFields;
import com.quizlet.db.data.models.persisted.fields.DBSelectedTermFields;
import com.quizlet.db.data.models.persisted.fields.DBSessionFields;
import com.quizlet.db.data.models.persisted.fields.DBStudySettingFields;
import com.quizlet.db.data.models.persisted.fields.DBTermFields;
import com.quizlet.db.data.models.persisted.fields.DBUserStudyableFields;
import com.quizlet.db.data.orm.Relationship;
import com.quizlet.features.infra.models.studymodeshared.StudyableModelData;
import com.quizlet.generated.enums.A1;
import com.quizlet.generated.enums.G1;
import com.quizlet.infra.legacysyncengine.datasources.o;
import com.quizlet.infra.legacysyncengine.datasources.s;
import com.quizlet.infra.legacysyncengine.net.request.g;
import io.reactivex.rxjava3.core.e;
import io.reactivex.rxjava3.core.i;
import io.reactivex.rxjava3.internal.operators.completable.l;
import io.reactivex.rxjava3.internal.operators.maybe.k;
import io.reactivex.rxjava3.internal.operators.observable.B;
import io.reactivex.rxjava3.internal.operators.observable.C4884c;
import io.reactivex.rxjava3.internal.operators.observable.C4885d;
import io.reactivex.rxjava3.internal.operators.observable.H;
import io.reactivex.rxjava3.internal.operators.observable.J;
import io.reactivex.rxjava3.subjects.f;
import io.reactivex.rxjava3.subjects.n;
import io.reactivex.rxjava3.subjects.p;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/* loaded from: classes3.dex */
public final class a {
    public DBSession C;
    public List D;
    public HashSet E;
    public final com.quizlet.qutils.rx.b F;
    public final G1 a;
    public final long b;
    public final io.reactivex.rxjava3.disposables.a c;
    public final ArrayList d;
    public final List e;
    public StudyableModel f;
    public final f g;
    public final p h;
    public final J i;
    public final C4884c j;
    public final i k;
    public final J l;
    public final J m;
    public final J n;
    public final B o;
    public final B p;
    public final B q;
    public final i r;
    public ArrayList s = new ArrayList();
    public List t = new ArrayList();
    public List u = new ArrayList();
    public List v = new ArrayList();
    public List w = new ArrayList();
    public List x = new ArrayList();
    public List y = new ArrayList();
    public ArrayList z = new ArrayList();
    public final com.quizlet.shared.usecase.folderstudymaterials.c A = new com.quizlet.shared.usecase.folderstudymaterials.c(26);
    public final C0219q B = new C0219q((Object) null);

    public a(long j, StudyableModelData studyableModelData, A1 a1, com.quizlet.infra.legacysyncengine.net.c cVar, com.quizlet.qutils.rx.b bVar, ArrayList arrayList, boolean z) {
        G1 studyableType = studyableModelData.getStudyableType();
        this.a = studyableType;
        long jK = studyableModelData.k();
        this.b = jK;
        Set setE = studyableModelData.e();
        io.reactivex.rxjava3.internal.functions.d.a(1, "maxSize");
        p pVar = new p(new n());
        this.h = pVar;
        pVar.b(Boolean.valueOf(z));
        this.g = new f();
        io.reactivex.rxjava3.disposables.a aVar = new io.reactivex.rxjava3.disposables.a();
        this.c = aVar;
        this.F = bVar;
        this.d = arrayList;
        com.quizlet.infra.legacysyncengine.orm.b bVar2 = new com.quizlet.infra.legacysyncengine.orm.b(Models.SELECTED_TERM);
        bVar2.c(DBSelectedTermFields.SET, setE, null);
        bVar2.b(Long.valueOf(j), DBSelectedTermFields.PERSON);
        o oVar = new o(cVar, bVar2.a());
        com.quizlet.infra.legacysyncengine.orm.b bVar3 = new com.quizlet.infra.legacysyncengine.orm.b(Models.TERM);
        Relationship<DBTerm, DBStudySet> relationship = DBTermFields.SET;
        bVar3.c(relationship, setE, null);
        bVar3.e(relationship);
        o oVar2 = new o(cVar, bVar3.a());
        ModelType modelClass = StudyableModel.getModelClass(studyableType);
        com.quizlet.infra.legacysyncengine.orm.b bVar4 = new com.quizlet.infra.legacysyncengine.orm.b(modelClass);
        bVar4.b(Long.valueOf(jK), ModelIdentityProvider.getSingleIdentityField(modelClass));
        o oVar3 = new o(cVar, bVar4.a());
        com.quizlet.infra.legacysyncengine.orm.b bVar5 = new com.quizlet.infra.legacysyncengine.orm.b(Models.SESSION);
        bVar5.b(Long.valueOf(j), DBSessionFields.PERSON);
        bVar5.d(DBSessionFields.STUDYABLE, Long.valueOf(jK), Long.valueOf(studyableType.b()));
        bVar5.b(Long.valueOf(studyableType.b()), DBSessionFields.ITEM_TYPE);
        bVar5.b(Long.valueOf(a1.a()), DBSessionFields.MODE_TYPE);
        bVar5.c(DBSessionFields.ENDED_TIMESTAMP, AbstractC3537t4.g(0L, -1L), null);
        HashSet hashSet = this.E;
        if (hashSet != null) {
            bVar5.b.addAll(hashSet);
        }
        o oVar4 = new o(cVar, bVar5.a());
        com.quizlet.infra.legacysyncengine.orm.b bVar6 = new com.quizlet.infra.legacysyncengine.orm.b(Models.STUDY_SETTING);
        bVar6.d(DBStudySettingFields.STUDYABLE, Long.valueOf(jK), Long.valueOf(studyableType.b()));
        bVar6.b(Long.valueOf(studyableType.b()), DBStudySettingFields.STUDYABLE_TYPE);
        bVar6.b(Long.valueOf(j), DBStudySettingFields.PERSON);
        o oVar5 = new o(cVar, bVar6.a());
        com.quizlet.infra.legacysyncengine.orm.b bVar7 = new com.quizlet.infra.legacysyncengine.orm.b(Models.IMAGE_REF);
        bVar7.b(Long.valueOf(jK), DBImageRefFields.MODEL_ID);
        bVar7.e(DBImageRefFields.IMAGE);
        o oVar6 = new o(cVar, bVar7.a());
        com.quizlet.infra.legacysyncengine.orm.b bVar8 = new com.quizlet.infra.legacysyncengine.orm.b(Models.DIAGRAM_SHAPE);
        bVar8.b(Long.valueOf(jK), DBDiagramShapeFields.SET_ID);
        o oVar7 = new o(cVar, bVar8.a());
        com.quizlet.infra.legacysyncengine.orm.b bVar9 = new com.quizlet.infra.legacysyncengine.orm.b(Models.USER_STUDYABLE);
        bVar9.b(Long.valueOf(j), DBUserStudyableFields.PERSON);
        bVar9.b(Long.valueOf(jK), DBUserStudyableFields.SET);
        bVar9.b(Long.valueOf(studyableType.b()), DBUserStudyableFields.STUDYABLE_TYPE);
        o oVar8 = new o(cVar, bVar9.a());
        this.e = Arrays.asList(oVar, oVar2, oVar3, oVar4, oVar5, oVar6, oVar7, oVar8);
        this.i = oVar.f().q(new b(this, 0));
        C4884c c4884cL = oVar2.f().l(new b(this, 7));
        this.j = c4884cL;
        this.k = i.e(c4884cL, this.i, pVar, new b(this, 8));
        this.l = oVar3.f().l(new com.quizlet.baserecyclerview.decoration.a(8)).q(new b(this, 9));
        this.m = oVar4.f().l(new com.quizlet.baserecyclerview.decoration.a(9)).q(new b(this, 1)).l(new b(this, 2)).q(new b(this, 3));
        this.n = oVar5.f().q(new b(this, 4));
        i iVarF = oVar6.f();
        c cVar2 = new c(this, 1);
        g gVar = io.reactivex.rxjava3.internal.functions.d.d;
        io.reactivex.rxjava3.internal.functions.b bVar10 = io.reactivex.rxjava3.internal.functions.d.c;
        this.o = new B(iVarF, cVar2, gVar, bVar10, bVar10);
        this.p = new B(oVar7.f(), new c(this, 2), gVar, bVar10, bVar10);
        this.q = new B(oVar8.f(), new c(this, 3), gVar, bVar10, bVar10);
        this.r = i.d(this.k, this.p, new b(this, 6));
        io.reactivex.rxjava3.disposables.b[] bVarArr = {this.i.t(), this.j.t(), this.k.t(), this.l.t(), this.m.t(), this.n.t(), this.o.t(), this.p.t(), this.q.t(), this.r.t()};
        if (!aVar.b) {
            synchronized (aVar) {
                try {
                    if (!aVar.b) {
                        K k = aVar.a;
                        if (k == null) {
                            k = new K(11);
                            aVar.a = k;
                        }
                        for (int i = 0; i < 10; i++) {
                            io.reactivex.rxjava3.disposables.b bVar11 = bVarArr[i];
                            Objects.requireNonNull(bVar11, "A Disposable in the disposables array is null");
                            k.b(bVar11);
                        }
                        return;
                    }
                } finally {
                }
            }
        }
        for (int i2 = 0; i2 < 10; i2++) {
            bVarArr[i2].dispose();
        }
    }

    public final List a() {
        if (d()) {
            return this.w;
        }
        throw new IllegalStateException("StudyModeDataProvider has not finished loading data");
    }

    public final List b() {
        if (d()) {
            return this.v;
        }
        throw new IllegalStateException("StudyModeDataProvider has not finished loading data");
    }

    public final boolean c() {
        if (d()) {
            return this.w.size() > 0;
        }
        throw new IllegalStateException("StudyModeDataProvider has not finished loading data");
    }

    public final boolean d() {
        f fVar = this.g;
        return fVar.a.get() == f.e && fVar.c == null;
    }

    public final void e() {
        C4885d c4885dX = new H(i.o(this.e).q(new com.quizlet.baserecyclerview.decoration.a(7)), io.reactivex.rxjava3.internal.functions.d.a, SubsamplingScaleImageView.TILE_SIZE_AUTO, e.a).x(16);
        b bVar = new b(this, 5);
        l lVar = new l(new c(this, 0), new com.quizlet.billing.subscriptions.c(2), new com.quizlet.eventlogger.e(this, 5));
        try {
            try {
                c4885dX.j(new k(new s(4, lVar, bVar), 0));
                this.c.b(lVar);
            } catch (NullPointerException e) {
                throw e;
            } catch (Throwable th) {
                x7.b(th);
                NullPointerException nullPointerException = new NullPointerException("subscribeActual failed");
                nullPointerException.initCause(th);
                throw nullPointerException;
            }
        } catch (NullPointerException e2) {
            throw e2;
        } catch (Throwable th2) {
            x7.b(th2);
            NullPointerException nullPointerException2 = new NullPointerException("subscribeActual failed");
            nullPointerException2.initCause(th2);
            throw nullPointerException2;
        }
    }

    public final void f() {
        Iterator it2 = this.e.iterator();
        while (it2.hasNext()) {
            ((o) it2.next()).g();
        }
        this.c.d();
    }
}
