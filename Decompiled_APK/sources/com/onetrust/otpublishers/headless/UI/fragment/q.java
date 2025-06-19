package com.onetrust.otpublishers.headless.UI.fragment;

import android.graphics.drawable.Drawable;
import android.view.View;
import androidx.appcompat.widget.d1;
import com.comscore.streaming.EventType;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectReader;
import com.google.android.gms.internal.ads.C3;
import com.j256.ormlite.dao.Dao;
import com.quizlet.api.HttpStatusRangeConstants;
import com.quizlet.data.model.S1;
import com.quizlet.db.data.database.DatabaseHelper;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.infra.legacysyncengine.net.exceptions.AccessNetException;
import com.quizlet.infra.legacysyncengine.net.exceptions.LoginRequiredNetException;
import com.quizlet.infra.legacysyncengine.net.exceptions.NotFoundNetException;
import com.quizlet.infra.legacysyncengine.net.exceptions.ServerNetException;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.C4622e;
import com.quizlet.quizletandroid.ui.activitycenter.views.UnreadBadgeView;
import com.quizlet.quizletandroid.ui.startpage.nav2.HideRecommendationFeedbackFragment;
import com.quizlet.remote.exceptions.NetException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import kotlin.collections.K;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class q implements d1, io.reactivex.rxjava3.functions.h, io.reactivex.rxjava3.functions.b, com.quizlet.local.ormlite.database.b, dagger.android.b, com.quizlet.quizletandroid.ui.activitycenter.views.f {
    public final /* synthetic */ int a;
    public Object b;

    public static NetException j(int i) {
        if (HttpStatusRangeConstants.a.a(Integer.valueOf(i))) {
            return null;
        }
        return i == 401 ? new LoginRequiredNetException(String.valueOf(i)) : i == 403 ? new AccessNetException(String.valueOf(i)) : (i == 404 || i == 410) ? new NotFoundNetException(String.valueOf(i)) : HttpStatusRangeConstants.c.a(Integer.valueOf(i)) ? new ServerNetException(String.valueOf(i)) : new NetException(String.valueOf(i));
    }

    public static void l(LinkedHashMap linkedHashMap, long j, S1 s1) {
        if (!linkedHashMap.containsKey(Long.valueOf(j))) {
            linkedHashMap.put(Long.valueOf(j), kotlin.collections.B.k(s1));
            return;
        }
        List list = (List) linkedHashMap.get(Long.valueOf(j));
        if (list != null) {
            list.add(s1);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object a(long r5, com.quizlet.generated.enums.y1 r7, java.lang.String r8, kotlin.coroutines.jvm.internal.c r9) {
        /*
            r4 = this;
            boolean r0 = r9 instanceof com.quizlet.data.interactor.folderstudymaterial.s
            if (r0 == 0) goto L13
            r0 = r9
            com.quizlet.data.interactor.folderstudymaterial.s r0 = (com.quizlet.data.interactor.folderstudymaterial.s) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.data.interactor.folderstudymaterial.s r0 = new com.quizlet.data.interactor.folderstudymaterial.s
            r0.<init>(r4, r9)
        L18:
            java.lang.Object r9 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L33
            if (r2 != r3) goto L2b
            androidx.glance.appwidget.protobuf.Z.e(r9)
            kotlin.r r9 = (kotlin.r) r9
            java.lang.Object r5 = r9.a
            goto L48
        L2b:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L33:
            androidx.glance.appwidget.protobuf.Z.e(r9)
            com.quizlet.data.model.I1 r9 = new com.quizlet.data.model.I1
            r9.<init>(r8, r7)
            r0.l = r3
            java.lang.Object r7 = r4.b
            com.quizlet.data.interactor.folderstudymaterial.z r7 = (com.quizlet.data.interactor.folderstudymaterial.z) r7
            java.lang.Object r5 = com.google.android.gms.internal.mlkit_vision_document_scanner.B6.a(r7, r9, r5, r0)
            if (r5 != r1) goto L48
            return r1
        L48:
            kotlin.p r6 = kotlin.r.b
            boolean r6 = r5 instanceof kotlin.q
            if (r6 != 0) goto L61
            com.quizlet.data.model.CreatedFolderStudyMaterial r5 = (com.quizlet.data.model.CreatedFolderStudyMaterial) r5
            com.quizlet.data.interactor.folderstudymaterial.h r6 = new com.quizlet.data.interactor.folderstudymaterial.h
            com.quizlet.data.interactor.folderstudymaterial.f r7 = new com.quizlet.data.interactor.folderstudymaterial.f
            long r8 = r5.b
            com.quizlet.generated.enums.y1 r0 = r5.d
            java.lang.String r5 = r5.c
            r7.<init>(r8, r5, r0)
            r6.<init>(r7)
            return r6
        L61:
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.UI.fragment.q.a(long, com.quizlet.generated.enums.y1, java.lang.String, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:4:0x0035  */
    @Override // io.reactivex.rxjava3.functions.b
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object apply(java.lang.Object r9, java.lang.Object r10) {
        /*
            r8 = this;
            java.lang.Long r9 = (java.lang.Long) r9
            java.lang.Integer r10 = (java.lang.Integer) r10
            java.lang.String r0 = "userId"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r9, r0)
            java.lang.String r0 = "timeStamp"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r10, r0)
            java.lang.Object r0 = r8.b
            com.quizlet.data.interactor.school.b r0 = (com.quizlet.data.interactor.school.b) r0
            java.lang.Object r0 = r0.b
            com.quizlet.features.setpage.upsell.a r0 = (com.quizlet.features.setpage.upsell.a) r0
            r9.longValue()
            int r10 = r10.intValue()
            long r1 = (long) r10
            java.lang.Object[] r10 = new java.lang.Object[]{r9}
            r3 = 1
            java.lang.String r4 = "explanations_upsell_dismissed_counter_%s"
            java.lang.String r5 = "format(...)"
            java.lang.String r10 = androidx.compose.animation.d0.s(r10, r3, r4, r5)
            android.content.SharedPreferences r0 = r0.a
            r6 = 0
            int r10 = r0.getInt(r10, r6)
            r7 = 2
            if (r10 < r7) goto L38
        L35:
            r3 = r6
            goto Laa
        L38:
            java.lang.Object[] r10 = new java.lang.Object[]{r9}
            java.lang.Object[] r10 = java.util.Arrays.copyOf(r10, r3)
            java.lang.String r10 = java.lang.String.format(r4, r10)
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r10, r5)
            boolean r10 = r0.contains(r10)
            if (r10 == 0) goto L9a
            java.lang.Object[] r10 = new java.lang.Object[]{r9}
            java.lang.String r10 = androidx.compose.animation.d0.s(r10, r3, r4, r5)
            int r10 = r0.getInt(r10, r6)
            if (r10 != r3) goto L35
            java.lang.Object[] r10 = new java.lang.Object[]{r9}
            java.lang.Object[] r10 = java.util.Arrays.copyOf(r10, r3)
            java.lang.String r10 = java.lang.String.format(r4, r10)
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r10, r5)
            boolean r10 = r0.contains(r10)
            if (r10 != 0) goto L71
            goto L35
        L71:
            java.lang.Object[] r9 = new java.lang.Object[]{r9}
            java.lang.String r10 = "explanations_upsell_last_dismissed_ts_%s"
            java.lang.String r9 = androidx.compose.animation.d0.s(r9, r3, r10, r5)
            r1 = -1
            long r9 = r0.getLong(r9, r1)
            r0 = 0
            int r0 = (r9 > r0 ? 1 : (r9 == r0 ? 0 : -1))
            if (r0 >= 0) goto L88
            goto L35
        L88:
            long r0 = com.quizlet.time.b.a()
            long r0 = r0 - r9
            java.util.concurrent.TimeUnit r9 = java.util.concurrent.TimeUnit.DAYS
            r10 = 5
            long r4 = (long) r10
            long r9 = r9.toSeconds(r4)
            int r9 = (r0 > r9 ? 1 : (r0 == r9 ? 0 : -1))
            if (r9 <= 0) goto L35
            goto Laa
        L9a:
            long r9 = com.quizlet.time.b.a()
            long r9 = r9 - r1
            java.util.concurrent.TimeUnit r0 = java.util.concurrent.TimeUnit.DAYS
            long r1 = (long) r7
            long r0 = r0.toSeconds(r1)
            int r9 = (r9 > r0 ? 1 : (r9 == r0 ? 0 : -1))
            if (r9 <= 0) goto L35
        Laa:
            java.lang.Boolean r9 = java.lang.Boolean.valueOf(r3)
            return r9
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.UI.fragment.q.apply(java.lang.Object, java.lang.Object):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object b(java.util.List r5, kotlin.coroutines.jvm.internal.c r6) {
        /*
            r4 = this;
            boolean r0 = r6 instanceof com.quizlet.data.repository.folderstudymaterial.a
            if (r0 == 0) goto L13
            r0 = r6
            com.quizlet.data.repository.folderstudymaterial.a r0 = (com.quizlet.data.repository.folderstudymaterial.a) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.data.repository.folderstudymaterial.a r0 = new com.quizlet.data.repository.folderstudymaterial.a
            r0.<init>(r4, r6)
        L18:
            java.lang.Object r6 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L33
            if (r2 != r3) goto L2b
            androidx.glance.appwidget.protobuf.Z.e(r6)
            kotlin.r r6 = (kotlin.r) r6
            java.lang.Object r5 = r6.a
            return r5
        L2b:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L33:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            r0.l = r3
            java.lang.Object r6 = r4.b
            com.quizlet.data.repository.qclass.c r6 = (com.quizlet.data.repository.qclass.c) r6
            java.lang.Object r5 = r6.b(r5, r0)
            if (r5 != r1) goto L43
            return r1
        L43:
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.UI.fragment.q.b(java.util.List, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    @Override // androidx.appcompat.widget.d1
    public boolean c(String query) {
        Intrinsics.checkNotNullParameter(query, "newText");
        int length = query.length();
        s sVar = (s) this.b;
        if (length == 0) {
            com.onetrust.otpublishers.headless.UI.viewmodel.d dVarS = sVar.S();
            dVarS.getClass();
            Intrinsics.checkNotNullParameter("", "query");
            dVarS.k = "";
            dVarS.B();
            return false;
        }
        com.onetrust.otpublishers.headless.UI.viewmodel.d dVarS2 = sVar.S();
        dVarS2.getClass();
        Intrinsics.checkNotNullParameter(query, "query");
        dVarS2.k = query;
        dVarS2.B();
        return false;
    }

    @Override // dagger.android.b
    public void d(Object obj) {
        HideRecommendationFeedbackFragment hideRecommendationFeedbackFragment = (HideRecommendationFeedbackFragment) obj;
        C4622e c4622e = (C4622e) this.b;
        hideRecommendationFeedbackFragment.q = c4622e.a();
        hideRecommendationFeedbackFragment.z = c4622e.e();
    }

    @Override // androidx.appcompat.widget.d1
    public boolean e(String query) {
        Intrinsics.checkNotNullParameter(query, "query");
        com.onetrust.otpublishers.headless.UI.viewmodel.d dVarS = ((s) this.b).S();
        dVarS.getClass();
        Intrinsics.checkNotNullParameter(query, "query");
        dVarS.k = query;
        dVarS.B();
        return false;
    }

    @Override // com.quizlet.local.ormlite.database.b
    public io.reactivex.rxjava3.internal.operators.completable.c f(List models) {
        Intrinsics.checkNotNullParameter(models, "models");
        Object value = ((kotlin.u) this.b).getValue();
        Intrinsics.checkNotNullExpressionValue(value, "getValue(...)");
        return com.quizlet.local.ormlite.util.b.a((Dao) value, models);
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object g(com.quizlet.generated.enums.I1 r5, kotlin.coroutines.jvm.internal.c r6) {
        /*
            r4 = this;
            boolean r0 = r6 instanceof com.quizlet.features.subjects.usecase.a
            if (r0 == 0) goto L13
            r0 = r6
            com.quizlet.features.subjects.usecase.a r0 = (com.quizlet.features.subjects.usecase.a) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.quizlet.features.subjects.usecase.a r0 = new com.quizlet.features.subjects.usecase.a
            r0.<init>(r4, r6)
        L18:
            java.lang.Object r6 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            if (r2 == 0) goto L31
            if (r2 != r3) goto L29
            com.quizlet.generated.enums.I1 r5 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L3f
        L29:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L31:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            r0.j = r5
            r0.m = r3
            java.io.Serializable r6 = r4.i(r0)
            if (r6 != r1) goto L3f
            return r1
        L3f:
            java.util.Map r6 = (java.util.Map) r6
            java.lang.Object r5 = kotlin.collections.V.d(r5, r6)
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.UI.fragment.q.g(com.quizlet.generated.enums.I1, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    @Override // com.quizlet.quizletandroid.ui.activitycenter.views.f
    public QTextView getCount() {
        QTextView count = ((UnreadBadgeView) this.b).q.c;
        Intrinsics.checkNotNullExpressionValue(count, "count");
        return count;
    }

    @Override // com.quizlet.quizletandroid.ui.activitycenter.views.f
    public View h() {
        View dot = ((UnreadBadgeView) this.b).q.d;
        Intrinsics.checkNotNullExpressionValue(dot, "dot");
        return dot;
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.io.Serializable i(kotlin.coroutines.jvm.internal.c r5) {
        /*
            r4 = this;
            boolean r0 = r5 instanceof com.quizlet.features.subjects.usecase.b
            if (r0 == 0) goto L13
            r0 = r5
            com.quizlet.features.subjects.usecase.b r0 = (com.quizlet.features.subjects.usecase.b) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.features.subjects.usecase.b r0 = new com.quizlet.features.subjects.usecase.b
            r0.<init>(r4, r5)
        L18:
            java.lang.Object r5 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L2f
            if (r2 != r3) goto L27
            androidx.glance.appwidget.protobuf.Z.e(r5)
            goto L3f
        L27:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r0)
            throw r5
        L2f:
            androidx.glance.appwidget.protobuf.Z.e(r5)
            r0.l = r3
            java.lang.Object r5 = r4.b
            com.quizlet.featuregate.features.folder.b r5 = (com.quizlet.featuregate.features.folder.b) r5
            java.lang.Enum r5 = r5.b(r0)
            if (r5 != r1) goto L3f
            return r1
        L3f:
            com.quizlet.features.subjects.model.c r5 = (com.quizlet.features.subjects.model.c) r5
            int r5 = r5.ordinal()
            if (r5 == 0) goto L6c
            if (r5 == r3) goto L67
            r0 = 2
            if (r5 == r0) goto L62
            r0 = 3
            if (r5 == r0) goto L5d
            r0 = 4
            if (r5 != r0) goto L57
            java.lang.Object r5 = com.quizlet.features.subjects.dataholder.d.a
            java.io.Serializable r5 = (java.io.Serializable) r5
            return r5
        L57:
            kotlin.NoWhenBranchMatchedException r5 = new kotlin.NoWhenBranchMatchedException
            r5.<init>()
            throw r5
        L5d:
            java.lang.Object r5 = com.quizlet.features.subjects.dataholder.b.a
            java.io.Serializable r5 = (java.io.Serializable) r5
            return r5
        L62:
            java.lang.Object r5 = com.quizlet.features.subjects.dataholder.e.a
            java.io.Serializable r5 = (java.io.Serializable) r5
            return r5
        L67:
            java.lang.Object r5 = com.quizlet.features.subjects.dataholder.c.a
            java.io.Serializable r5 = (java.io.Serializable) r5
            return r5
        L6c:
            java.lang.Object r5 = com.quizlet.features.subjects.dataholder.a.a
            java.io.Serializable r5 = (java.io.Serializable) r5
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.UI.fragment.q.i(kotlin.coroutines.jvm.internal.c):java.io.Serializable");
    }

    public io.reactivex.rxjava3.core.p k(List list) {
        io.reactivex.rxjava3.internal.operators.flowable.b bVarB;
        io.reactivex.rxjava3.internal.operators.flowable.b bVarB2;
        ArrayList arrayListM = assistantMode.refactored.a.m("ids", list);
        ArrayList arrayList = new ArrayList();
        for (Object obj : list) {
            if (((Number) obj).longValue() < 0) {
                arrayListM.add(obj);
            } else {
                arrayList.add(obj);
            }
        }
        com.quizlet.local.ormlite.database.dao.e eVar = com.quizlet.local.ormlite.database.dao.e.a;
        com.quizlet.features.settings.composables.x xVar = new com.quizlet.features.settings.composables.x(1, eVar, com.quizlet.local.ormlite.database.dao.e.class, "queryByIds", "queryByIds(Ljava/util/Collection;)Ljava/lang/String;", 0, 24);
        boolean zIsEmpty = arrayList.isEmpty();
        kotlin.u uVar = (kotlin.u) this.b;
        if (zIsEmpty) {
            bVarB = io.reactivex.rxjava3.core.p.f(K.a);
        } else {
            Object value = uVar.getValue();
            Intrinsics.checkNotNullExpressionValue(value, "getValue(...)");
            bVarB = com.quizlet.local.ormlite.util.b.b((Dao) value, (String) xVar.invoke(arrayList));
        }
        com.quizlet.features.settings.composables.x xVar2 = new com.quizlet.features.settings.composables.x(1, eVar, com.quizlet.local.ormlite.database.dao.e.class, "queryByLocalIds", "queryByLocalIds(Ljava/util/Collection;)Ljava/lang/String;", 0, 25);
        if (arrayListM.isEmpty()) {
            bVarB2 = io.reactivex.rxjava3.core.p.f(K.a);
        } else {
            Object value2 = uVar.getValue();
            Intrinsics.checkNotNullExpressionValue(value2, "getValue(...)");
            bVarB2 = com.quizlet.local.ormlite.util.b.b((Dao) value2, (String) xVar2.invoke(arrayListM));
        }
        io.reactivex.rxjava3.core.p pVarP = io.reactivex.rxjava3.core.p.p(bVarB, bVarB2, new com.google.mlkit.common.internal.model.a(28));
        Intrinsics.checkNotNullExpressionValue(pVarP, "Single.zip(s1, s2, BiFun…-> zipper.invoke(t, u) })");
        return pVarP;
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object m(java.lang.String r5, int r6, kotlin.coroutines.jvm.internal.c r7) {
        /*
            r4 = this;
            boolean r0 = r7 instanceof com.quizlet.data.interactor.school.i
            if (r0 == 0) goto L13
            r0 = r7
            com.quizlet.data.interactor.school.i r0 = (com.quizlet.data.interactor.school.i) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.data.interactor.school.i r0 = new com.quizlet.data.interactor.school.i
            r0.<init>(r4, r7)
        L18:
            java.lang.Object r7 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L2f
            if (r2 != r3) goto L27
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L49
        L27:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L2f:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            r0.l = r3
            java.lang.Object r7 = r4.b
            com.quizlet.data.repository.set.f r7 = (com.quizlet.data.repository.set.f) r7
            com.quizlet.remote.model.school.f r2 = new com.quizlet.remote.model.school.f
            r3 = 0
            r2.<init>(r7, r5, r6, r3)
            java.lang.Object r5 = r7.d
            kotlinx.coroutines.y r5 = (kotlinx.coroutines.AbstractC5040y) r5
            java.lang.Object r7 = kotlinx.coroutines.E.J(r5, r2, r0)
            if (r7 != r1) goto L49
            return r1
        L49:
            com.quizlet.data.model.x1 r7 = (com.quizlet.data.model.C4180x1) r7
            java.util.List r5 = r7.a
            boolean r5 = r5.isEmpty()
            java.lang.String r6 = "School not found."
            if (r5 != 0) goto La5
            java.util.ArrayList r5 = new java.util.ArrayList
            r5.<init>()
            java.util.List r0 = r7.a
            java.util.Iterator r0 = r0.iterator()
        L60:
            boolean r1 = r0.hasNext()
            if (r1 == 0) goto L87
            java.lang.Object r1 = r0.next()
            r2 = r1
            com.quizlet.data.model.School r2 = (com.quizlet.data.model.School) r2
            java.lang.String r3 = r2.b
            if (r3 == 0) goto L60
            int r3 = r3.length()
            if (r3 != 0) goto L78
            goto L60
        L78:
            java.lang.String r2 = r2.j
            if (r2 == 0) goto L60
            int r2 = r2.length()
            if (r2 != 0) goto L83
            goto L60
        L83:
            r5.add(r1)
            goto L60
        L87:
            boolean r0 = r5.isEmpty()
            if (r0 != 0) goto L9f
            java.lang.String r6 = "schools"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r5, r6)
            java.lang.String r6 = r7.b
            java.lang.String r7 = "searchSessionId"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r6, r7)
            com.quizlet.data.model.x1 r7 = new com.quizlet.data.model.x1
            r7.<init>(r6, r5)
            return r7
        L9f:
            com.quizlet.data.repository.school.exceptions.SchoolNotFoundException r5 = new com.quizlet.data.repository.school.exceptions.SchoolNotFoundException
            r5.<init>(r6)
            throw r5
        La5:
            com.quizlet.data.repository.school.exceptions.SchoolNotFoundException r5 = new com.quizlet.data.repository.school.exceptions.SchoolNotFoundException
            r5.<init>(r6)
            throw r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.UI.fragment.q.m(java.lang.String, int, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object n(java.lang.String r5, java.lang.String r6, kotlin.coroutines.jvm.internal.c r7) throws java.lang.Throwable {
        /*
            r4 = this;
            boolean r0 = r7 instanceof com.quizlet.data.interactor.course.g
            if (r0 == 0) goto L13
            r0 = r7
            com.quizlet.data.interactor.course.g r0 = (com.quizlet.data.interactor.course.g) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.data.interactor.course.g r0 = new com.quizlet.data.interactor.course.g
            r0.<init>(r4, r7)
        L18:
            java.lang.Object r7 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L2f
            if (r2 != r3) goto L27
            androidx.glance.appwidget.protobuf.Z.e(r7)     // Catch: java.lang.Exception -> L4c
            goto L49
        L27:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L2f:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            java.lang.Object r7 = r4.b     // Catch: java.lang.Exception -> L4c
            androidx.work.impl.model.n r7 = (androidx.work.impl.model.n) r7     // Catch: java.lang.Exception -> L4c
            r0.l = r3     // Catch: java.lang.Exception -> L4c
            com.quizlet.remote.model.course.g r2 = new com.quizlet.remote.model.course.g     // Catch: java.lang.Exception -> L4c
            r3 = 0
            r2.<init>(r7, r5, r6, r3)     // Catch: java.lang.Exception -> L4c
            java.lang.Object r5 = r7.d     // Catch: java.lang.Exception -> L4c
            kotlinx.coroutines.y r5 = (kotlinx.coroutines.AbstractC5040y) r5     // Catch: java.lang.Exception -> L4c
            java.lang.Object r7 = kotlinx.coroutines.E.J(r5, r2, r0)     // Catch: java.lang.Exception -> L4c
            if (r7 != r1) goto L49
            return r1
        L49:
            com.quizlet.data.model.Course r7 = (com.quizlet.data.model.Course) r7     // Catch: java.lang.Exception -> L4c
            return r7
        L4c:
            com.quizlet.data.repository.course.exceptions.GetCourseException r5 = new com.quizlet.data.repository.course.exceptions.GetCourseException
            r5.<init>()
            throw r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.UI.fragment.q.n(java.lang.String, java.lang.String, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object o(kotlin.coroutines.jvm.internal.c r5) {
        /*
            r4 = this;
            boolean r0 = r5 instanceof com.quizlet.data.interactor.user.delete.a
            if (r0 == 0) goto L13
            r0 = r5
            com.quizlet.data.interactor.user.delete.a r0 = (com.quizlet.data.interactor.user.delete.a) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.data.interactor.user.delete.a r0 = new com.quizlet.data.interactor.user.delete.a
            r0.<init>(r4, r5)
        L18:
            java.lang.Object r5 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L33
            if (r2 != r3) goto L2b
            androidx.glance.appwidget.protobuf.Z.e(r5)
            kotlin.r r5 = (kotlin.r) r5
            java.lang.Object r5 = r5.a
            return r5
        L2b:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r0)
            throw r5
        L33:
            androidx.glance.appwidget.protobuf.Z.e(r5)
            r0.l = r3
            java.lang.Object r5 = r4.b
            com.quizlet.remote.model.user.delete.c r5 = (com.quizlet.remote.model.user.delete.c) r5
            java.lang.Object r5 = r5.b(r0)
            if (r5 != r1) goto L43
            return r1
        L43:
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.UI.fragment.q.o(kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public com.quizlet.data.repository.widget.b p(String url) {
        Intrinsics.checkNotNullParameter(url, "url");
        com.quizlet.qutils.data.offline.c ttl = com.quizlet.qutils.data.offline.c.b;
        Intrinsics.checkNotNullParameter(url, "url");
        Intrinsics.checkNotNullParameter(ttl, "ttl");
        com.quizlet.quizletandroid.ui.common.images.loading.offline.a aVar = new com.quizlet.quizletandroid.ui.common.images.loading.offline.a(url);
        com.bumptech.glide.m mVar = (com.bumptech.glide.m) this.b;
        mVar.getClass();
        return new com.quizlet.data.repository.widget.b(new com.bumptech.glide.k(mVar.a, mVar, Drawable.class, mVar.b).D(aVar));
    }

    /* JADX WARN: Removed duplicated region for block: B:8:0x0014  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object q(com.quizlet.data.interactor.folderstudymaterial.g r8, kotlin.coroutines.jvm.internal.c r9) {
        /*
            Method dump skipped, instructions count: 205
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.UI.fragment.q.q(com.quizlet.data.interactor.folderstudymaterial.g, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object r(java.lang.String r5, com.quizlet.generated.enums.y1 r6, java.util.List r7, java.util.List r8, kotlin.coroutines.jvm.internal.c r9) {
        /*
            r4 = this;
            boolean r0 = r9 instanceof com.quizlet.data.interactor.folderstudymaterial.u
            if (r0 == 0) goto L13
            r0 = r9
            com.quizlet.data.interactor.folderstudymaterial.u r0 = (com.quizlet.data.interactor.folderstudymaterial.u) r0
            int r1 = r0.p
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.p = r1
            goto L18
        L13:
            com.quizlet.data.interactor.folderstudymaterial.u r0 = new com.quizlet.data.interactor.folderstudymaterial.u
            r0.<init>(r4, r9)
        L18:
            java.lang.Object r9 = r0.n
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.p
            r3 = 1
            if (r2 == 0) goto L3b
            if (r2 != r3) goto L33
            java.util.List r8 = r0.m
            java.util.List r7 = r0.l
            com.quizlet.generated.enums.y1 r6 = r0.k
            java.lang.String r5 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r9)
            kotlin.r r9 = (kotlin.r) r9
            java.lang.Object r9 = r9.a
            goto L58
        L33:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L3b:
            androidx.glance.appwidget.protobuf.Z.e(r9)
            com.quizlet.data.model.I1 r9 = new com.quizlet.data.model.I1
            r9.<init>(r5, r6)
            r0.j = r5
            r0.k = r6
            r0.l = r7
            r0.m = r8
            r0.p = r3
            java.lang.Object r2 = r4.b
            com.quizlet.data.interactor.folderstudymaterial.z r2 = (com.quizlet.data.interactor.folderstudymaterial.z) r2
            java.lang.Object r9 = r2.b(r9, r7, r8, r0)
            if (r9 != r1) goto L58
            return r1
        L58:
            kotlin.p r0 = kotlin.r.b
            boolean r0 = r9 instanceof kotlin.q
            if (r0 != 0) goto L6a
            com.quizlet.data.model.v1 r9 = (com.quizlet.data.model.C4174v1) r9
            com.quizlet.data.interactor.folderstudymaterial.h r9 = new com.quizlet.data.interactor.folderstudymaterial.h
            com.quizlet.data.interactor.folderstudymaterial.e r0 = new com.quizlet.data.interactor.folderstudymaterial.e
            r0.<init>(r5, r6, r8, r7)
            r9.<init>(r0)
        L6a:
            return r9
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.UI.fragment.q.r(java.lang.String, com.quizlet.generated.enums.y1, java.util.List, java.util.List, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object s(com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.c r14, kotlin.coroutines.jvm.internal.c r15) throws java.lang.Throwable {
        /*
            r13 = this;
            boolean r0 = r15 instanceof com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.usecase.a
            if (r0 == 0) goto L13
            r0 = r15
            com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.usecase.a r0 = (com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.usecase.a) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.usecase.a r0 = new com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.usecase.a
            r0.<init>(r13, r15)
        L18:
            java.lang.Object r15 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 0
            r4 = 1
            if (r2 == 0) goto L35
            if (r2 != r4) goto L2d
            com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.c r14 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r15)     // Catch: java.lang.Exception -> L2a
            goto L5e
        L2a:
            r0 = move-exception
            r14 = r0
            goto L85
        L2d:
            java.lang.IllegalStateException r14 = new java.lang.IllegalStateException
            java.lang.String r15 = "call to 'resume' before 'invoke' with coroutine"
            r14.<init>(r15)
            throw r14
        L35:
            androidx.glance.appwidget.protobuf.Z.e(r15)
            com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.b r15 = r14.i     // Catch: java.lang.Exception -> L2a
            com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.b r2 = com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.b.a     // Catch: java.lang.Exception -> L2a
            if (r15 != r2) goto L82
            java.lang.Object r15 = r13.b     // Catch: java.lang.Exception -> L2a
            com.google.firebase.crashlytics.internal.settings.b r15 = (com.google.firebase.crashlytics.internal.settings.b) r15     // Catch: java.lang.Exception -> L2a
            java.lang.String r2 = r14.b     // Catch: java.lang.Exception -> L2a
            java.lang.String r5 = ""
            r0.j = r14     // Catch: java.lang.Exception -> L2a
            r0.m = r4     // Catch: java.lang.Exception -> L2a
            java.lang.Object r15 = r15.b     // Catch: java.lang.Exception -> L2a
            androidx.work.impl.model.n r15 = (androidx.work.impl.model.n) r15     // Catch: java.lang.Exception -> L2a
            com.quizlet.remote.model.course.d r6 = new com.quizlet.remote.model.course.d     // Catch: java.lang.Exception -> L2a
            r6.<init>(r15, r2, r5, r3)     // Catch: java.lang.Exception -> L2a
            java.lang.Object r15 = r15.d     // Catch: java.lang.Exception -> L2a
            kotlinx.coroutines.y r15 = (kotlinx.coroutines.AbstractC5040y) r15     // Catch: java.lang.Exception -> L2a
            java.lang.Object r15 = kotlinx.coroutines.E.J(r15, r6, r0)     // Catch: java.lang.Exception -> L2a
            if (r15 != r1) goto L5e
            return r1
        L5e:
            com.quizlet.data.model.Course r15 = (com.quizlet.data.model.Course) r15     // Catch: java.lang.Exception -> L2a
            java.lang.String r14 = r14.b     // Catch: java.lang.Exception -> L2a
            long r6 = r15.a     // Catch: java.lang.Exception -> L2a
            java.lang.String r0 = r15.b     // Catch: java.lang.Exception -> L2a
            if (r0 == 0) goto L70
            boolean r1 = kotlin.text.StringsKt.O(r0)     // Catch: java.lang.Exception -> L2a
            r1 = r1 ^ r4
            if (r1 != r4) goto L70
            r3 = r0
        L70:
            if (r3 != 0) goto L74
            r8 = r14
            goto L75
        L74:
            r8 = r3
        L75:
            com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.b r10 = com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.b.b     // Catch: java.lang.Exception -> L2a
            com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.c r5 = new com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.c     // Catch: java.lang.Exception -> L2a
            java.lang.String r9 = r15.e     // Catch: java.lang.Exception -> L2a
            r11 = 0
            r12 = 48
            r5.<init>(r6, r8, r9, r10, r11, r12)     // Catch: java.lang.Exception -> L2a
            r14 = r5
        L82:
            kotlin.p r15 = kotlin.r.b     // Catch: java.lang.Exception -> L2a
            return r14
        L85:
            kotlin.p r15 = kotlin.r.b
            kotlin.q r14 = androidx.glance.appwidget.protobuf.Z.b(r14)
            return r14
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.UI.fragment.q.s(com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.c, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object t(long r5, com.quizlet.generated.enums.y1 r7, java.lang.String r8, kotlin.coroutines.jvm.internal.c r9) {
        /*
            r4 = this;
            boolean r0 = r9 instanceof com.quizlet.data.interactor.folderstudymaterial.v
            if (r0 == 0) goto L13
            r0 = r9
            com.quizlet.data.interactor.folderstudymaterial.v r0 = (com.quizlet.data.interactor.folderstudymaterial.v) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.data.interactor.folderstudymaterial.v r0 = new com.quizlet.data.interactor.folderstudymaterial.v
            r0.<init>(r4, r9)
        L18:
            java.lang.Object r9 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L33
            if (r2 != r3) goto L2b
            androidx.glance.appwidget.protobuf.Z.e(r9)
            kotlin.r r9 = (kotlin.r) r9
            java.lang.Object r5 = r9.a
            goto L48
        L2b:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L33:
            androidx.glance.appwidget.protobuf.Z.e(r9)
            com.quizlet.data.model.I1 r9 = new com.quizlet.data.model.I1
            r9.<init>(r8, r7)
            r0.l = r3
            java.lang.Object r7 = r4.b
            com.quizlet.data.interactor.folderstudymaterial.z r7 = (com.quizlet.data.interactor.folderstudymaterial.z) r7
            java.lang.Object r5 = com.google.android.gms.internal.mlkit_vision_document_scanner.B6.b(r7, r9, r5, r0)
            if (r5 != r1) goto L48
            return r1
        L48:
            kotlin.p r6 = kotlin.r.b
            boolean r6 = r5 instanceof kotlin.q
            if (r6 != 0) goto L61
            com.quizlet.data.model.DeletedFolderStudyMaterial r5 = (com.quizlet.data.model.DeletedFolderStudyMaterial) r5
            com.quizlet.data.interactor.folderstudymaterial.h r6 = new com.quizlet.data.interactor.folderstudymaterial.h
            com.quizlet.data.interactor.folderstudymaterial.d r7 = new com.quizlet.data.interactor.folderstudymaterial.d
            long r8 = r5.b
            com.quizlet.generated.enums.y1 r0 = r5.d
            java.lang.String r5 = r5.c
            r7.<init>(r8, r5, r0)
            r6.<init>(r7)
            return r6
        L61:
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.UI.fragment.q.t(long, com.quizlet.generated.enums.y1, java.lang.String, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object u(kotlin.coroutines.jvm.internal.c r5) throws java.lang.Throwable {
        /*
            r4 = this;
            boolean r0 = r5 instanceof com.quizlet.data.interactor.achievements.h
            if (r0 == 0) goto L13
            r0 = r5
            com.quizlet.data.interactor.achievements.h r0 = (com.quizlet.data.interactor.achievements.h) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.data.interactor.achievements.h r0 = new com.quizlet.data.interactor.achievements.h
            r0.<init>(r4, r5)
        L18:
            java.lang.Object r5 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L31
            if (r2 != r3) goto L29
            androidx.glance.appwidget.protobuf.Z.e(r5)     // Catch: java.lang.Exception -> L27
            goto L4e
        L27:
            r5 = move-exception
            goto L51
        L29:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r0)
            throw r5
        L31:
            androidx.glance.appwidget.protobuf.Z.e(r5)
            java.lang.Object r5 = r4.b     // Catch: java.lang.Exception -> L27
            com.quizlet.data.repository.achievements.h r5 = (com.quizlet.data.repository.achievements.h) r5     // Catch: java.lang.Exception -> L27
            r0.l = r3     // Catch: java.lang.Exception -> L27
            r5.getClass()     // Catch: java.lang.Exception -> L27
            com.quizlet.data.repository.achievements.e r2 = new com.quizlet.data.repository.achievements.e     // Catch: java.lang.Exception -> L27
            r3 = 0
            r2.<init>(r5, r3)     // Catch: java.lang.Exception -> L27
            java.lang.Object r5 = r5.c     // Catch: java.lang.Exception -> L27
            kotlinx.coroutines.y r5 = (kotlinx.coroutines.AbstractC5040y) r5     // Catch: java.lang.Exception -> L27
            java.lang.Object r5 = kotlinx.coroutines.E.J(r5, r2, r0)     // Catch: java.lang.Exception -> L27
            if (r5 != r1) goto L4e
            return r1
        L4e:
            com.quizlet.data.model.o r5 = (com.quizlet.data.model.AbstractC4152o) r5     // Catch: java.lang.Exception -> L27
            return r5
        L51:
            com.quizlet.data.model.m r0 = new com.quizlet.data.model.m
            r0.<init>(r5)
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.UI.fragment.q.u(kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public /* synthetic */ q(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    public q(com.quizlet.remote.model.user.delete.c repository) {
        this.a = 8;
        Intrinsics.checkNotNullParameter(repository, "repository");
        this.b = repository;
    }

    public q(com.quizlet.time.b timeUtils) {
        this.a = 23;
        Intrinsics.checkNotNullParameter(timeUtils, "timeUtils");
        this.b = timeUtils;
    }

    public q(C3 practiceTestsRepository) {
        this.a = 6;
        Intrinsics.checkNotNullParameter(practiceTestsRepository, "practiceTestsRepository");
        this.b = practiceTestsRepository;
    }

    public q(com.quizlet.data.repository.explanations.myexplanations.a folderSetRemoteDataStore) {
        this.a = 13;
        Intrinsics.checkNotNullParameter(folderSetRemoteDataStore, "folderSetRemoteDataStore");
        this.b = folderSetRemoteDataStore;
    }

    public q(EventLogger eventLogger) {
        this.a = 17;
        Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
        this.b = eventLogger;
    }

    public q(com.quizlet.remote.model.notes.e notesRepository) {
        this.a = 5;
        Intrinsics.checkNotNullParameter(notesRepository, "notesRepository");
        this.b = notesRepository;
    }

    public q(com.google.firebase.crashlytics.internal.settings.b createNewCourseUseCase) {
        this.a = 16;
        Intrinsics.checkNotNullParameter(createNewCourseUseCase, "createNewCourseUseCase");
        this.b = createNewCourseUseCase;
    }

    public q(androidx.work.impl.model.n repository) {
        this.a = 3;
        Intrinsics.checkNotNullParameter(repository, "repository");
        this.b = repository;
    }

    public q(com.quizlet.data.repository.achievements.h repository) {
        this.a = 2;
        Intrinsics.checkNotNullParameter(repository, "repository");
        this.b = repository;
    }

    public q(com.quizlet.data.repository.set.f repository) {
        this.a = 7;
        Intrinsics.checkNotNullParameter(repository, "repository");
        this.b = repository;
    }

    public q(com.quizlet.quizletandroid.util.o timestampFormatter) {
        this.a = 27;
        Intrinsics.checkNotNullParameter(timestampFormatter, "timestampFormatter");
        this.b = timestampFormatter;
    }

    public q(com.quizlet.data.repository.qclass.c dataStore) {
        this.a = 10;
        Intrinsics.checkNotNullParameter(dataStore, "dataStore");
        this.b = dataStore;
    }

    public q(com.bumptech.glide.m mRequestManager) {
        this.a = 29;
        Intrinsics.checkNotNullParameter(mRequestManager, "mRequestManager");
        this.b = mRequestManager;
    }

    public q(com.quizlet.featuregate.features.flexiblegrading.a longTextFeature) {
        this.a = 15;
        Intrinsics.checkNotNullParameter(longTextFeature, "longTextFeature");
        this.b = longTextFeature;
    }

    public q(com.quizlet.featuregate.features.folder.b subjectCountryUseCase) {
        this.a = 19;
        Intrinsics.checkNotNullParameter(subjectCountryUseCase, "subjectCountryUseCase");
        this.b = subjectCountryUseCase;
    }

    public q(com.quizlet.infra.legacysyncengine.net.c loader) {
        this.a = 25;
        Intrinsics.checkNotNullParameter(loader, "loader");
        this.b = loader;
    }

    public q(DatabaseHelper database) {
        this.a = 21;
        Intrinsics.checkNotNullParameter(database, "database");
        this.b = kotlin.l.b(new com.quizlet.local.ormlite.database.dao.a(database, 7));
    }

    public q(ObjectReader objectReader, okhttp3.s sVar) {
        this.a = 20;
        this.b = sVar;
        if (objectReader.getConfig().isEnabled(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)) {
            timber.log.c.a(new IllegalStateException("ObjectReader must not fail on unknown properties"));
        }
    }

    public q(com.quizlet.data.interactor.folderstudymaterial.z saveStudyMaterialToFolderUseCase) {
        this.a = 4;
        Intrinsics.checkNotNullParameter(saveStudyMaterialToFolderUseCase, "saveStudyMaterialToFolderUseCase");
        this.b = saveStudyMaterialToFolderUseCase;
    }

    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        switch (this.a) {
            case 9:
                List p0 = (List) obj;
                Intrinsics.checkNotNullParameter(p0, "p0");
                return ((com.quizlet.local.ormlite.models.bookmark.a) this.b).a(p0);
            case 11:
                final com.quizlet.data.repository.folderwithcreatorinclass.a remoteData = (com.quizlet.data.repository.folderwithcreatorinclass.a) obj;
                Intrinsics.checkNotNullParameter(remoteData, "remoteData");
                final com.quizlet.data.repository.folderwithcreatorinclass.e eVar = (com.quizlet.data.repository.folderwithcreatorinclass.e) this.b;
                final int i = 0;
                Object obj2 = null;
                io.reactivex.rxjava3.internal.operators.completable.m mVar = new io.reactivex.rxjava3.internal.operators.completable.m(((com.quizlet.local.ormlite.models.bookmark.a) eVar.b).a(remoteData.a), new io.reactivex.rxjava3.functions.h() { // from class: com.quizlet.data.repository.folderwithcreatorinclass.c
                    @Override // io.reactivex.rxjava3.functions.h
                    public final Object apply(Object obj3) {
                        Throwable e = (Throwable) obj3;
                        switch (i) {
                            case 0:
                                Intrinsics.checkNotNullParameter(e, "e");
                                ((org.slf4j.b) eVar.e).j("Error importing remote ClassFolder data", e);
                                return remoteData.a;
                            default:
                                Intrinsics.checkNotNullParameter(e, "e");
                                ((org.slf4j.b) eVar.e).j("Error importing remote FolderWithCreator data", e);
                                return remoteData.b;
                        }
                    }
                }, obj2, 2);
                Intrinsics.checkNotNullExpressionValue(mVar, "onErrorReturn(...)");
                final int i2 = 1;
                io.reactivex.rxjava3.internal.operators.completable.m mVar2 = new io.reactivex.rxjava3.internal.operators.completable.m(((com.quizlet.local.ormlite.models.bookmark.a) eVar.c).a(remoteData.b), new io.reactivex.rxjava3.functions.h() { // from class: com.quizlet.data.repository.folderwithcreatorinclass.c
                    @Override // io.reactivex.rxjava3.functions.h
                    public final Object apply(Object obj3) {
                        Throwable e = (Throwable) obj3;
                        switch (i2) {
                            case 0:
                                Intrinsics.checkNotNullParameter(e, "e");
                                ((org.slf4j.b) eVar.e).j("Error importing remote ClassFolder data", e);
                                return remoteData.a;
                            default:
                                Intrinsics.checkNotNullParameter(e, "e");
                                ((org.slf4j.b) eVar.e).j("Error importing remote FolderWithCreator data", e);
                                return remoteData.b;
                        }
                    }
                }, obj2, 2);
                Intrinsics.checkNotNullExpressionValue(mVar2, "onErrorReturn(...)");
                io.reactivex.rxjava3.core.p pVarP = io.reactivex.rxjava3.core.p.p(mVar, mVar2, new com.quizlet.data.repository.folderwithcreatorinclass.d());
                Intrinsics.checkNotNullExpressionValue(pVarP, "Single.zip(s1, s2, BiFun…-> zipper.invoke(t, u) })");
                return pVarP;
            case 12:
                Throwable e = (Throwable) obj;
                Intrinsics.checkNotNullParameter(e, "e");
                ((org.slf4j.b) ((com.quizlet.data.repository.studysetwithcreatorinclass.g) this.b).f).h("Error retrieving StudySetWithCreatorInClass data from remote", e);
                return io.reactivex.rxjava3.internal.operators.observable.E.a;
            case 14:
                Boolean isPaidTeacher = (Boolean) obj;
                Intrinsics.checkNotNullParameter(isPaidTeacher, "isPaidTeacher");
                if (!isPaidTeacher.booleanValue()) {
                    return ((androidx.work.impl.model.c) this.b).y().g(com.quizlet.featuregate.contracts.properties.d.c);
                }
                return io.reactivex.rxjava3.core.p.f(Boolean.TRUE);
            case EventType.WINDOW_STATE /* 22 */:
                List modelsWithIds = (List) obj;
                Intrinsics.checkNotNullParameter(modelsWithIds, "modelsWithIds");
                com.quizlet.local.ormlite.models.bookmark.a aVar = (com.quizlet.local.ormlite.models.bookmark.a) this.b;
                return new io.reactivex.rxjava3.internal.operators.completable.m(((com.quizlet.data.interactor.course.a) aVar.d).f(modelsWithIds), null, Boolean.TRUE, 0).g(new com.quizlet.data.repository.qclass.c(22, modelsWithIds, aVar));
            default:
                List it2 = (List) obj;
                Intrinsics.checkNotNullParameter(it2, "it");
                com.quizlet.quizletandroid.data.management.b bVar = (com.quizlet.quizletandroid.data.management.b) this.b;
                bVar.a.onComplete();
                return new io.reactivex.rxjava3.internal.operators.single.b(new io.reactivex.rxjava3.internal.operators.flowable.b(bVar.a, 1));
        }
    }
}
