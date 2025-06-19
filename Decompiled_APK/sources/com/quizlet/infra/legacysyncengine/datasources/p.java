package com.quizlet.infra.legacysyncengine.datasources;

import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.quizlet.db.data.models.persisted.base.Models;
import com.quizlet.db.data.models.persisted.fields.DBAnswerFields;
import com.quizlet.db.data.models.persisted.fields.DBGroupMembershipFields;
import com.quizlet.db.data.models.persisted.fields.DBQuestionAttributeFields;
import com.quizlet.db.data.models.persisted.fields.DBSessionFields;
import com.quizlet.db.data.models.persisted.fields.DBStudySetFields;
import com.quizlet.generated.enums.A1;
import com.quizlet.generated.enums.G1;
import io.reactivex.rxjava3.internal.operators.observable.C4885d;
import io.reactivex.rxjava3.internal.operators.observable.J;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class p extends c {
    public final /* synthetic */ int b;
    public final com.quizlet.infra.legacysyncengine.net.c c;
    public final com.quizlet.infra.legacysyncengine.orm.query.a d;
    public final io.reactivex.rxjava3.subjects.d e;
    public Object f;
    public Object g;
    public Object h;

    public p(long j, long j2, com.quizlet.infra.legacysyncengine.net.c loader) {
        this.b = 2;
        Intrinsics.checkNotNullParameter(loader, "loader");
        this.c = loader;
        com.quizlet.infra.legacysyncengine.orm.b bVar = new com.quizlet.infra.legacysyncengine.orm.b(Models.QUESTION_ATTRIBUTE);
        bVar.b(Long.valueOf(j), DBQuestionAttributeFields.SET_ID);
        bVar.b(Long.valueOf(j2), DBQuestionAttributeFields.PERSON_ID);
        com.quizlet.infra.legacysyncengine.orm.query.a aVarA = bVar.a();
        Intrinsics.checkNotNullExpressionValue(aVarA, "build(...)");
        this.d = aVarA;
        io.reactivex.rxjava3.subjects.d dVarZ = io.reactivex.rxjava3.subjects.d.z();
        Intrinsics.checkNotNullExpressionValue(dVarZ, "create(...)");
        this.e = dVarZ;
        io.reactivex.rxjava3.disposables.d dVar = new io.reactivex.rxjava3.disposables.d(io.reactivex.rxjava3.internal.functions.d.b, 0);
        Intrinsics.checkNotNullExpressionValue(dVar, "empty(...)");
        this.f = dVar;
        com.jakewharton.rxbinding4.a aVar = new com.jakewharton.rxbinding4.a(new com.google.firebase.tracing.a(13, this, aVarA), 3);
        Intrinsics.checkNotNullExpressionValue(aVar, "create(...)");
        io.reactivex.rxjava3.internal.operators.maybe.h hVar = new io.reactivex.rxjava3.internal.operators.maybe.h(0, aVar.j().g(r.d), r.e);
        Intrinsics.checkNotNullExpressionValue(hVar, "filter(...)");
        io.reactivex.rxjava3.internal.operators.completable.c cVar = new io.reactivex.rxjava3.internal.operators.completable.c(new io.reactivex.rxjava3.internal.operators.flowable.b(io.reactivex.rxjava3.core.g.d(hVar, new io.reactivex.rxjava3.internal.operators.maybe.e(dVarZ.j(), 3)), 0), 6);
        Intrinsics.checkNotNullExpressionValue(cVar, "ignoreElement(...)");
        this.g = cVar;
        this.h = new f(this, 4);
    }

    /* JADX WARN: Type inference failed for: r3v10, types: [io.reactivex.rxjava3.disposables.b, java.util.concurrent.atomic.AtomicReference] */
    /* JADX WARN: Type inference failed for: r3v16, types: [io.reactivex.rxjava3.disposables.b, java.util.concurrent.atomic.AtomicReference] */
    @Override // com.quizlet.infra.legacysyncengine.datasources.c
    public final void a(b listener) {
        switch (this.b) {
            case 0:
                ConcurrentHashMap.KeySetView keySetView = this.a;
                if (keySetView.remove(listener) && keySetView.size() == 0) {
                    io.reactivex.rxjava3.internal.observers.h hVar = (io.reactivex.rxjava3.internal.observers.h) this.h;
                    if (hVar != null) {
                        io.reactivex.rxjava3.internal.disposables.a.a(hVar);
                        this.h = null;
                    }
                    this.c.a(this.d, (f) this.f);
                    break;
                }
                break;
            case 1:
                Intrinsics.checkNotNullParameter(listener, "listener");
                ConcurrentHashMap.KeySetView keySetView2 = this.a;
                if (keySetView2.remove(listener) && keySetView2.size() == 0) {
                    ((AtomicReference) this.f).dispose();
                    this.c.a(this.d, (f) this.h);
                    break;
                }
                break;
            case 2:
                Intrinsics.checkNotNullParameter(listener, "listener");
                ConcurrentHashMap.KeySetView keySetView3 = this.a;
                if (keySetView3.remove(listener) && keySetView3.size() == 0) {
                    ((AtomicReference) this.f).dispose();
                    this.c.a(this.d, (f) this.h);
                    break;
                }
                break;
            default:
                ConcurrentHashMap.KeySetView keySetView4 = this.a;
                if (keySetView4.remove(listener) && keySetView4.size() == 0) {
                    io.reactivex.rxjava3.internal.observers.h hVar2 = (io.reactivex.rxjava3.internal.observers.h) this.h;
                    if (hVar2 != null) {
                        io.reactivex.rxjava3.internal.disposables.a.a(hVar2);
                        this.h = null;
                    }
                    this.c.a(this.d, (f) this.f);
                    break;
                }
                break;
        }
    }

    @Override // com.quizlet.infra.legacysyncengine.datasources.c
    public final List b() {
        switch (this.b) {
            case 0:
                return ((HashSet) this.g) == null ? Collections.EMPTY_LIST : new ArrayList((HashSet) this.g);
            case 1:
                ArrayList arrayListD = this.c.d(this.d);
                if (arrayListD == null) {
                    return null;
                }
                C4885d c4885dX = io.reactivex.rxjava3.core.i.o(arrayListD).x(16);
                Intrinsics.checkNotNullExpressionValue(c4885dX, "toList(...)");
                return (List) c4885dX.b();
            case 2:
                ArrayList arrayListD2 = this.c.d(this.d);
                if (arrayListD2 == null) {
                    return null;
                }
                C4885d c4885dX2 = io.reactivex.rxjava3.core.i.o(arrayListD2).x(16);
                Intrinsics.checkNotNullExpressionValue(c4885dX2, "toList(...)");
                return (List) c4885dX2.b();
            default:
                return ((HashSet) this.g) == null ? Collections.EMPTY_LIST : new ArrayList((HashSet) this.g);
        }
    }

    /* JADX WARN: Type inference failed for: r0v10, types: [io.reactivex.rxjava3.disposables.b, java.util.concurrent.atomic.AtomicReference] */
    /* JADX WARN: Type inference failed for: r0v14, types: [io.reactivex.rxjava3.disposables.b, java.util.concurrent.atomic.AtomicReference] */
    @Override // com.quizlet.infra.legacysyncengine.datasources.c
    public final io.reactivex.rxjava3.core.i d() {
        switch (this.b) {
            case 0:
                return new io.reactivex.rxjava3.internal.operators.mixed.b(1, new J(this.c.b(this.d, com.quizlet.infra.legacysyncengine.net.b.a).m(), new com.quizlet.baserecyclerview.decoration.a(11), 2).l(new com.quizlet.baserecyclerview.decoration.a(15)).q(new com.quizlet.baserecyclerview.decoration.a(16)).x(16).g(new com.quizlet.baserecyclerview.decoration.a(14)), new com.google.android.material.search.a(this, 24));
            case 1:
                ((AtomicReference) this.f).dispose();
                io.reactivex.rxjava3.subjects.p pVarC = this.c.c(this.d, com.quizlet.infra.legacysyncengine.net.c.e);
                this.f = (AtomicReference) pVarC.u(new com.quizlet.analytics.marketing.e(this, 13), io.reactivex.rxjava3.internal.functions.d.e, io.reactivex.rxjava3.internal.functions.d.c);
                return pVarC;
            case 2:
                ((AtomicReference) this.f).dispose();
                io.reactivex.rxjava3.subjects.p pVarC2 = this.c.c(this.d, com.quizlet.infra.legacysyncengine.net.c.e);
                this.f = (AtomicReference) pVarC2.u(new com.quizlet.analytics.marketing.e(this, 14), io.reactivex.rxjava3.internal.functions.d.e, io.reactivex.rxjava3.internal.functions.d.c);
                return pVarC2;
            default:
                return new io.reactivex.rxjava3.internal.operators.mixed.b(1, new J(this.c.b(this.d, com.quizlet.infra.legacysyncengine.net.b.a).m(), new com.quizlet.baserecyclerview.decoration.a(11), 2).q(new com.quizlet.baserecyclerview.decoration.a(23)).x(16).g(new com.quizlet.baserecyclerview.decoration.a(14)), new x(this, 1)).q(new com.quizlet.baserecyclerview.decoration.a(24)).q(new com.quizlet.baserecyclerview.decoration.a(14)).m(new x(this, 2), SubsamplingScaleImageView.TILE_SIZE_AUTO);
        }
    }

    @Override // com.quizlet.infra.legacysyncengine.datasources.c
    public final boolean e(b bVar) {
        switch (this.b) {
            case 0:
                boolean zE = super.e(bVar);
                if (zE && this.a.size() == 1) {
                    this.h = (io.reactivex.rxjava3.internal.observers.h) this.e.u(new com.quizlet.billing.subscriptions.a(this, 6), new com.quizlet.billing.subscriptions.c(3), io.reactivex.rxjava3.internal.functions.d.c);
                    this.c.e(this.d, (f) this.f);
                }
                return zE;
            case 1:
                boolean zE2 = super.e(bVar);
                if (zE2 && this.a.size() == 1) {
                    this.c.e(this.d, (f) this.h);
                }
                return zE2;
            case 2:
                boolean zE3 = super.e(bVar);
                if (zE3 && this.a.size() == 1) {
                    this.c.e(this.d, (f) this.h);
                }
                return zE3;
            default:
                boolean zE4 = super.e(bVar);
                if (zE4 && this.a.size() == 1) {
                    this.h = (io.reactivex.rxjava3.internal.observers.h) this.e.m(new x(this, 0), SubsamplingScaleImageView.TILE_SIZE_AUTO).u(new com.quizlet.billing.subscriptions.a(this, 7), io.reactivex.rxjava3.internal.functions.d.e, io.reactivex.rxjava3.internal.functions.d.c);
                    this.c.e(this.d, (f) this.f);
                }
                return zE4;
        }
    }

    public p(com.quizlet.infra.legacysyncengine.net.c loader, long j, long j2, A1 modeType) {
        this.b = 1;
        Intrinsics.checkNotNullParameter(loader, "loader");
        Intrinsics.checkNotNullParameter(modeType, "modeType");
        this.c = loader;
        com.quizlet.infra.legacysyncengine.orm.b bVar = new com.quizlet.infra.legacysyncengine.orm.b(Models.ANSWER);
        bVar.b(Long.valueOf(j), DBAnswerFields.SET);
        bVar.b(Long.valueOf(modeType.a()), DBAnswerFields.MODE_TYPE);
        bVar.b(Long.valueOf(j2), DBAnswerFields.PERSON);
        com.quizlet.infra.legacysyncengine.orm.query.a aVarA = bVar.a();
        Intrinsics.checkNotNullExpressionValue(aVarA, "build(...)");
        this.d = aVarA;
        io.reactivex.rxjava3.subjects.d dVarZ = io.reactivex.rxjava3.subjects.d.z();
        Intrinsics.checkNotNullExpressionValue(dVarZ, "create(...)");
        this.e = dVarZ;
        io.reactivex.rxjava3.disposables.d dVar = new io.reactivex.rxjava3.disposables.d(io.reactivex.rxjava3.internal.functions.d.b, 0);
        Intrinsics.checkNotNullExpressionValue(dVar, "empty(...)");
        this.f = dVar;
        com.jakewharton.rxbinding4.a aVar = new com.jakewharton.rxbinding4.a(new com.google.firebase.tracing.a(12, this, aVarA), 3);
        Intrinsics.checkNotNullExpressionValue(aVar, "create(...)");
        io.reactivex.rxjava3.internal.operators.maybe.h hVar = new io.reactivex.rxjava3.internal.operators.maybe.h(0, aVar.j().g(r.b), r.c);
        Intrinsics.checkNotNullExpressionValue(hVar, "filter(...)");
        io.reactivex.rxjava3.internal.operators.completable.c cVar = new io.reactivex.rxjava3.internal.operators.completable.c(new io.reactivex.rxjava3.internal.operators.flowable.b(io.reactivex.rxjava3.core.g.d(hVar, new io.reactivex.rxjava3.internal.operators.maybe.e(dVarZ.j(), 3)), 0), 6);
        Intrinsics.checkNotNullExpressionValue(cVar, "ignoreElement(...)");
        this.g = cVar;
        this.h = new f(this, 3);
    }

    public p(com.quizlet.infra.legacysyncengine.net.c cVar, Long l, int i) {
        this.b = i;
        switch (i) {
            case 3:
                this.e = io.reactivex.rxjava3.subjects.d.z();
                this.c = cVar;
                com.quizlet.infra.legacysyncengine.orm.b bVar = new com.quizlet.infra.legacysyncengine.orm.b(Models.GROUP_MEMBERSHIP);
                bVar.b(l, DBGroupMembershipFields.USER);
                bVar.e(DBGroupMembershipFields.CLASS);
                this.d = bVar.a();
                this.f = new f(this, 5);
                break;
            default:
                this.e = io.reactivex.rxjava3.subjects.d.z();
                this.c = cVar;
                com.quizlet.infra.legacysyncengine.orm.b bVar2 = new com.quizlet.infra.legacysyncengine.orm.b(Models.SESSION);
                bVar2.b(l, DBSessionFields.PERSON);
                bVar2.b(Long.valueOf(G1.SET.b()), DBSessionFields.ITEM_TYPE);
                bVar2.e(DBSessionFields.STUDYABLE, DBStudySetFields.CREATOR);
                this.d = bVar2.a();
                this.f = new f(this, 2);
                break;
        }
    }
}
