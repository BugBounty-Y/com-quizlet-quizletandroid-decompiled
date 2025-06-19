package com.lyft.android.scissors;

import android.content.pm.PackageManager;
import android.net.Uri;
import android.view.View;
import androidx.datastore.core.InterfaceC1076h;
import androidx.work.impl.r;
import com.google.android.gms.internal.mlkit_vision_camera.I1;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3714r6;
import com.j256.ormlite.dao.Dao;
import com.quizlet.api.di.ApiModule;
import com.quizlet.api.di.OkHttpModule;
import com.quizlet.db.data.database.DatabaseHelper;
import com.quizlet.db.data.models.base.DBModel;
import com.quizlet.db.data.models.persisted.DBBookmark;
import com.quizlet.db.data.models.persisted.DBFolder;
import com.quizlet.local.datastore.preferences.C4567d;
import com.quizlet.quizletandroid.D;
import com.quizlet.quizletandroid.u;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlin.collections.F;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class b implements io.reactivex.rxjava3.functions.h, com.quizlet.features.infra.legacyadapter.d, io.reactivex.rxjava3.functions.b, com.quizlet.local.ormlite.database.b {
    public final /* synthetic */ int a;
    public final Object b;

    public /* synthetic */ b(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    public Object a(kotlin.coroutines.jvm.internal.c cVar) {
        io.reactivex.rxjava3.internal.operators.flowable.b bVar = new io.reactivex.rxjava3.internal.operators.flowable.b(new com.quizlet.data.repository.activitycenter.a((com.quizlet.data.repository.activitycenter.b) this.b, 0), 4);
        Intrinsics.checkNotNullExpressionValue(bVar, "defer(...)");
        return I1.b(bVar, cVar);
    }

    @Override // io.reactivex.rxjava3.functions.b
    public Object apply(Object t1, Object t2) {
        Intrinsics.checkNotNullExpressionValue(t1, "t1");
        Intrinsics.checkNotNullExpressionValue(t2, "t2");
        List list = (List) t2;
        List list2 = (List) t1;
        Intrinsics.d(list2);
        Intrinsics.d(list);
        ((com.quizlet.infra.legacysyncengine.datasources.n) this.b).getClass();
        ArrayList arrayList = new ArrayList(list2);
        Iterator it2 = list.iterator();
        while (it2.hasNext()) {
            DBFolder folder = ((DBBookmark) it2.next()).getFolder();
            if (folder != null) {
                arrayList.add(folder);
            }
        }
        arrayList.removeIf(new com.quizlet.features.folders.addtofolder.viewmodel.a(1, new com.quizlet.features.universaluploadflow.flashcards.d(4)));
        if (arrayList.size() > 1) {
            F.t(arrayList, new com.quizlet.infra.legacysyncengine.datasources.l());
        }
        return arrayList;
    }

    @Override // com.quizlet.features.infra.legacyadapter.d
    public boolean b(View view, int i, DBModel dBModel) {
        com.quizlet.features.infra.legacyadapter.d dVar = (com.quizlet.features.infra.legacyadapter.d) this.b;
        if (dVar == null) {
            return false;
        }
        return dVar.b(view, i, dBModel);
    }

    public u c() {
        return new u(new ApiModule(), new com.onetrust.otpublishers.headless.Internal.Helper.h(29), new dagger.hilt.android.internal.modules.a((D) this.b), new com.quizlet.shared.usecase.folderstudymaterials.a(29), new com.quizlet.shared.usecase.studiableMetadata.a(27), new com.google.mlkit.common.sdkinternal.b(26), new com.quizlet.shared.usecase.folderstudymaterials.b(29), new com.quizlet.shared.usecase.folderstudymaterials.c(29), new com.quizlet.quizletandroid.injection.modules.a(), new com.quizlet.shared.usecase.folderstudymaterials.d(29), new OkHttpModule(), new com.google.firebase.heartbeatinfo.e(28), new com.quizlet.shared.usecase.srs.a(29), new com.quizlet.quizletandroid.ui.common.ads.prebid.creators.a(4), new com.quizlet.shared.usecase.studiableMetadata.a(29), new com.quizlet.quizletandroid.ui.login.di.a(0), new retrofit2.adapter.rxjava3.d(29));
    }

    @Override // com.quizlet.features.infra.legacyadapter.d
    public boolean d(View view, int i, DBModel dBModel) {
        com.quizlet.features.infra.legacyadapter.d dVar = (com.quizlet.features.infra.legacyadapter.d) this.b;
        if (dVar == null) {
            return false;
        }
        return dVar.d(view, i, dBModel);
    }

    public com.quizlet.billing.model.b e() {
        return AbstractC3714r6.b(((com.quizlet.infra.legacysyncengine.managers.d) this.b).r);
    }

    @Override // com.quizlet.local.ormlite.database.b
    public io.reactivex.rxjava3.internal.operators.completable.c f(List models) {
        Intrinsics.checkNotNullParameter(models, "models");
        return com.quizlet.local.ormlite.util.b.a(g(), models);
    }

    public Dao g() {
        Object value = ((kotlin.u) this.b).getValue();
        Intrinsics.checkNotNullExpressionValue(value, "getValue(...)");
        return (Dao) value;
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object h(long r5, kotlin.coroutines.jvm.internal.c r7) {
        /*
            r4 = this;
            boolean r0 = r7 instanceof com.quizlet.local.datastore.preferences.S
            if (r0 == 0) goto L13
            r0 = r7
            com.quizlet.local.datastore.preferences.S r0 = (com.quizlet.local.datastore.preferences.S) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.quizlet.local.datastore.preferences.S r0 = new com.quizlet.local.datastore.preferences.S
            r0.<init>(r4, r7)
        L18:
            java.lang.Object r7 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            if (r2 == 0) goto L31
            if (r2 != r3) goto L29
            androidx.datastore.preferences.core.f r5 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L6a
        L29:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L31:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            java.lang.Long r7 = new java.lang.Long
            r7.<init>(r5)
            java.lang.Object[] r5 = new java.lang.Object[]{r7}
            java.lang.Object[] r5 = java.util.Arrays.copyOf(r5, r3)
            java.lang.String r6 = "user_onboarding_ell_exams_%s"
            java.lang.String r5 = java.lang.String.format(r6, r5)
            java.lang.String r6 = "format(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r5, r6)
            java.lang.String r6 = "name"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r5, r6)
            androidx.datastore.preferences.core.f r6 = new androidx.datastore.preferences.core.f
            r6.<init>(r5)
            java.lang.Object r5 = r4.b
            androidx.datastore.core.h r5 = (androidx.datastore.core.InterfaceC1076h) r5
            kotlinx.coroutines.flow.i r5 = r5.getData()
            r0.j = r6
            r0.m = r3
            java.lang.Object r7 = kotlinx.coroutines.flow.e0.p(r5, r0)
            if (r7 != r1) goto L69
            return r1
        L69:
            r5 = r6
        L6a:
            androidx.datastore.preferences.core.b r7 = (androidx.datastore.preferences.core.b) r7
            java.lang.Object r5 = r7.c(r5)
            java.util.Set r5 = (java.util.Set) r5
            if (r5 != 0) goto L76
            kotlin.collections.M r5 = kotlin.collections.M.a
        L76:
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.lyft.android.scissors.b.h(long, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object i(long r5, kotlin.coroutines.jvm.internal.c r7) {
        /*
            r4 = this;
            boolean r0 = r7 instanceof com.quizlet.local.datastore.preferences.T
            if (r0 == 0) goto L13
            r0 = r7
            com.quizlet.local.datastore.preferences.T r0 = (com.quizlet.local.datastore.preferences.T) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.quizlet.local.datastore.preferences.T r0 = new com.quizlet.local.datastore.preferences.T
            r0.<init>(r4, r7)
        L18:
            java.lang.Object r7 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            if (r2 == 0) goto L31
            if (r2 != r3) goto L29
            androidx.datastore.preferences.core.f r5 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L63
        L29:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L31:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            java.lang.Long r7 = new java.lang.Long
            r7.<init>(r5)
            java.lang.Object[] r5 = new java.lang.Object[]{r7}
            java.lang.Object[] r5 = java.util.Arrays.copyOf(r5, r3)
            java.lang.String r6 = "user_onboarding_session_count_%s"
            java.lang.String r5 = java.lang.String.format(r6, r5)
            java.lang.String r6 = "format(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r5, r6)
            androidx.datastore.preferences.core.f r5 = com.google.android.gms.internal.mlkit_vision_barcode.R6.c(r5)
            java.lang.Object r6 = r4.b
            androidx.datastore.core.h r6 = (androidx.datastore.core.InterfaceC1076h) r6
            kotlinx.coroutines.flow.i r6 = r6.getData()
            r0.j = r5
            r0.m = r3
            java.lang.Object r7 = kotlinx.coroutines.flow.e0.p(r6, r0)
            if (r7 != r1) goto L63
            return r1
        L63:
            androidx.datastore.preferences.core.b r7 = (androidx.datastore.preferences.core.b) r7
            java.lang.Object r5 = r7.c(r5)
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.lyft.android.scissors.b.i(long, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object j(long r5, kotlin.coroutines.jvm.internal.c r7) {
        /*
            r4 = this;
            boolean r0 = r7 instanceof com.quizlet.local.datastore.preferences.U
            if (r0 == 0) goto L13
            r0 = r7
            com.quizlet.local.datastore.preferences.U r0 = (com.quizlet.local.datastore.preferences.U) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.quizlet.local.datastore.preferences.U r0 = new com.quizlet.local.datastore.preferences.U
            r0.<init>(r4, r7)
        L18:
            java.lang.Object r7 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            if (r2 == 0) goto L31
            if (r2 != r3) goto L29
            androidx.datastore.preferences.core.f r5 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L63
        L29:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L31:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            java.lang.Long r7 = new java.lang.Long
            r7.<init>(r5)
            java.lang.Object[] r5 = new java.lang.Object[]{r7}
            java.lang.Object[] r5 = java.util.Arrays.copyOf(r5, r3)
            java.lang.String r6 = "user_is_studying_english_%s"
            java.lang.String r5 = java.lang.String.format(r6, r5)
            java.lang.String r6 = "format(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r5, r6)
            androidx.datastore.preferences.core.f r5 = com.google.android.gms.internal.mlkit_vision_barcode.R6.a(r5)
            java.lang.Object r6 = r4.b
            androidx.datastore.core.h r6 = (androidx.datastore.core.InterfaceC1076h) r6
            kotlinx.coroutines.flow.i r6 = r6.getData()
            r0.j = r5
            r0.m = r3
            java.lang.Object r7 = kotlinx.coroutines.flow.e0.p(r6, r0)
            if (r7 != r1) goto L63
            return r1
        L63:
            androidx.datastore.preferences.core.b r7 = (androidx.datastore.preferences.core.b) r7
            java.lang.Object r5 = r7.c(r5)
            java.lang.Boolean r5 = (java.lang.Boolean) r5
            if (r5 == 0) goto L72
            boolean r5 = r5.booleanValue()
            goto L73
        L72:
            r5 = 0
        L73:
            java.lang.Boolean r5 = java.lang.Boolean.valueOf(r5)
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.lyft.android.scissors.b.j(long, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object k(long r5, kotlin.coroutines.jvm.internal.c r7) {
        /*
            r4 = this;
            boolean r0 = r7 instanceof com.quizlet.local.datastore.preferences.V
            if (r0 == 0) goto L13
            r0 = r7
            com.quizlet.local.datastore.preferences.V r0 = (com.quizlet.local.datastore.preferences.V) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.quizlet.local.datastore.preferences.V r0 = new com.quizlet.local.datastore.preferences.V
            r0.<init>(r4, r7)
        L18:
            java.lang.Object r7 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            if (r2 == 0) goto L31
            if (r2 != r3) goto L29
            androidx.datastore.preferences.core.f r5 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L63
        L29:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L31:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            java.lang.Long r7 = new java.lang.Long
            r7.<init>(r5)
            java.lang.Object[] r5 = new java.lang.Object[]{r7}
            java.lang.Object[] r5 = java.util.Arrays.copyOf(r5, r3)
            java.lang.String r6 = "user_completed_onboarding_ell_%s"
            java.lang.String r5 = java.lang.String.format(r6, r5)
            java.lang.String r6 = "format(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r5, r6)
            androidx.datastore.preferences.core.f r5 = com.google.android.gms.internal.mlkit_vision_barcode.R6.a(r5)
            java.lang.Object r6 = r4.b
            androidx.datastore.core.h r6 = (androidx.datastore.core.InterfaceC1076h) r6
            kotlinx.coroutines.flow.i r6 = r6.getData()
            r0.j = r5
            r0.m = r3
            java.lang.Object r7 = kotlinx.coroutines.flow.e0.p(r6, r0)
            if (r7 != r1) goto L63
            return r1
        L63:
            androidx.datastore.preferences.core.b r7 = (androidx.datastore.preferences.core.b) r7
            java.lang.Object r5 = r7.c(r5)
            java.lang.Boolean r5 = (java.lang.Boolean) r5
            if (r5 == 0) goto L72
            boolean r5 = r5.booleanValue()
            goto L73
        L72:
            r5 = 0
        L73:
            java.lang.Boolean r5 = java.lang.Boolean.valueOf(r5)
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.lyft.android.scissors.b.k(long, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Code restructure failed: missing block: B:23:0x0091, code lost:
    
        if (r8 == r1) goto L24;
     */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object l(long r6, kotlin.coroutines.jvm.internal.c r8) {
        /*
            r5 = this;
            boolean r0 = r8 instanceof com.quizlet.local.datastore.preferences.W
            if (r0 == 0) goto L13
            r0 = r8
            com.quizlet.local.datastore.preferences.W r0 = (com.quizlet.local.datastore.preferences.W) r0
            int r1 = r0.n
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.n = r1
            goto L18
        L13:
            com.quizlet.local.datastore.preferences.W r0 = new com.quizlet.local.datastore.preferences.W
            r0.<init>(r5, r8)
        L18:
            java.lang.Object r8 = r0.l
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.n
            r3 = 2
            r4 = 1
            if (r2 == 0) goto L3a
            if (r2 == r4) goto L32
            if (r2 != r3) goto L2a
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L94
        L2a:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r7 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r7)
            throw r6
        L32:
            androidx.datastore.preferences.core.f r6 = r0.k
            com.lyft.android.scissors.b r7 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L6f
        L3a:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            java.lang.Long r8 = new java.lang.Long
            r8.<init>(r6)
            java.lang.Object[] r6 = new java.lang.Object[]{r8}
            java.lang.Object[] r6 = java.util.Arrays.copyOf(r6, r4)
            java.lang.String r7 = "user_onboarding_session_count_%s"
            java.lang.String r6 = java.lang.String.format(r7, r6)
            java.lang.String r7 = "format(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r6, r7)
            androidx.datastore.preferences.core.f r6 = com.google.android.gms.internal.mlkit_vision_barcode.R6.c(r6)
            java.lang.Object r7 = r5.b
            androidx.datastore.core.h r7 = (androidx.datastore.core.InterfaceC1076h) r7
            kotlinx.coroutines.flow.i r7 = r7.getData()
            r0.j = r5
            r0.k = r6
            r0.n = r4
            java.lang.Object r8 = kotlinx.coroutines.flow.e0.p(r7, r0)
            if (r8 != r1) goto L6e
            goto L93
        L6e:
            r7 = r5
        L6f:
            androidx.datastore.preferences.core.b r8 = (androidx.datastore.preferences.core.b) r8
            java.lang.Object r8 = r8.c(r6)
            java.lang.Integer r8 = (java.lang.Integer) r8
            if (r8 == 0) goto L96
            int r8 = r8.intValue()
            java.lang.Object r7 = r7.b
            androidx.datastore.core.h r7 = (androidx.datastore.core.InterfaceC1076h) r7
            com.quizlet.local.datastore.preferences.X r2 = new com.quizlet.local.datastore.preferences.X
            r4 = 0
            r2.<init>(r6, r8, r4)
            r0.j = r4
            r0.k = r4
            r0.n = r3
            java.lang.Object r8 = com.google.android.gms.internal.mlkit_vision_barcode.S6.d(r7, r2, r0)
            if (r8 != r1) goto L94
        L93:
            return r1
        L94:
            androidx.datastore.preferences.core.b r8 = (androidx.datastore.preferences.core.b) r8
        L96:
            kotlin.Unit r6 = kotlin.Unit.a
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: com.lyft.android.scissors.b.l(long, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object m(com.quizlet.data.model.TitleInfo r6, java.lang.String r7, kotlin.coroutines.jvm.internal.c r8) throws java.lang.Throwable {
        /*
            r5 = this;
            boolean r0 = r8 instanceof com.quizlet.data.interactor.notes.j
            if (r0 == 0) goto L13
            r0 = r8
            com.quizlet.data.interactor.notes.j r0 = (com.quizlet.data.interactor.notes.j) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.data.interactor.notes.j r0 = new com.quizlet.data.interactor.notes.j
            r0.<init>(r5, r8)
        L18:
            java.lang.Object r8 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 0
            r4 = 1
            if (r2 == 0) goto L32
            if (r2 != r4) goto L2a
            androidx.glance.appwidget.protobuf.Z.e(r8)     // Catch: java.lang.Exception -> L28
            goto L4f
        L28:
            r6 = move-exception
            goto L57
        L2a:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r7 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r7)
            throw r6
        L32:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            if (r6 == 0) goto L60
            java.lang.Object r8 = r5.b     // Catch: java.lang.Exception -> L28
            com.quizlet.remote.model.notes.e r8 = (com.quizlet.remote.model.notes.e) r8     // Catch: java.lang.Exception -> L28
            java.lang.String r6 = r6.a     // Catch: java.lang.Exception -> L28
            r0.l = r4     // Catch: java.lang.Exception -> L28
            com.quizlet.remote.model.notes.d r2 = new com.quizlet.remote.model.notes.d     // Catch: java.lang.Exception -> L28
            r2.<init>(r7, r8, r6, r3)     // Catch: java.lang.Exception -> L28
            java.lang.Object r6 = r8.c     // Catch: java.lang.Exception -> L28
            kotlinx.coroutines.y r6 = (kotlinx.coroutines.AbstractC5040y) r6     // Catch: java.lang.Exception -> L28
            java.lang.Object r8 = kotlinx.coroutines.E.J(r6, r2, r0)     // Catch: java.lang.Exception -> L28
            if (r8 != r1) goto L4f
            return r1
        L4f:
            java.lang.String r6 = "null cannot be cast to non-null type com.quizlet.data.model.TitleInfo"
            kotlin.jvm.internal.Intrinsics.e(r8, r6)     // Catch: java.lang.Exception -> L28
            com.quizlet.data.model.TitleInfo r8 = (com.quizlet.data.model.TitleInfo) r8     // Catch: java.lang.Exception -> L28
            return r8
        L57:
            com.quizlet.data.exceptions.notes.UpdateTitleException r7 = new com.quizlet.data.exceptions.notes.UpdateTitleException
            r6.getMessage()
            r7.<init>(r3)
            throw r7
        L60:
            return r3
        */
        throw new UnsupportedOperationException("Method not decompiled: com.lyft.android.scissors.b.m(com.quizlet.data.model.TitleInfo, java.lang.String, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Code restructure failed: missing block: B:32:0x008a, code lost:
    
        if (r9 == r1) goto L33;
     */
    /* JADX WARN: Removed duplicated region for block: B:28:0x006e  */
    /* JADX WARN: Removed duplicated region for block: B:35:0x008f  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object n(java.util.LinkedHashSet r8, kotlin.coroutines.jvm.internal.c r9) throws java.lang.Throwable {
        /*
            r7 = this;
            boolean r0 = r9 instanceof com.quizlet.features.folders.viewmodel.usecases.t
            if (r0 == 0) goto L13
            r0 = r9
            com.quizlet.features.folders.viewmodel.usecases.t r0 = (com.quizlet.features.folders.viewmodel.usecases.t) r0
            int r1 = r0.n
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.n = r1
            goto L18
        L13:
            com.quizlet.features.folders.viewmodel.usecases.t r0 = new com.quizlet.features.folders.viewmodel.usecases.t
            r0.<init>(r7, r9)
        L18:
            java.lang.Object r9 = r0.l
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.n
            r3 = 0
            r4 = 2
            r5 = 0
            r6 = 1
            if (r2 == 0) goto L3c
            if (r2 == r6) goto L36
            if (r2 != r4) goto L2e
            int r8 = r0.k
            androidx.glance.appwidget.protobuf.Z.e(r9)
            goto L8d
        L2e:
            java.lang.IllegalStateException r8 = new java.lang.IllegalStateException
            java.lang.String r9 = "call to 'resume' before 'invoke' with coroutine"
            r8.<init>(r9)
            throw r8
        L36:
            com.lyft.android.scissors.b r8 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r9)
            goto L5e
        L3c:
            androidx.glance.appwidget.protobuf.Z.e(r9)
            boolean r8 = r8.isEmpty()
            if (r8 == 0) goto L69
            r0.j = r7
            r0.n = r6
            java.lang.Object r8 = r7.b
            androidx.work.impl.model.l r8 = (androidx.work.impl.model.l) r8
            com.quizlet.data.interactor.folder.n r9 = new com.quizlet.data.interactor.folder.n
            r9.<init>(r8, r5)
            java.lang.Object r8 = r8.c
            kotlinx.coroutines.y r8 = (kotlinx.coroutines.AbstractC5040y) r8
            java.lang.Object r9 = kotlinx.coroutines.E.J(r8, r9, r0)
            if (r9 != r1) goto L5d
            goto L8c
        L5d:
            r8 = r7
        L5e:
            java.lang.Boolean r9 = (java.lang.Boolean) r9
            boolean r9 = r9.booleanValue()
            if (r9 != 0) goto L6a
            r9 = r8
            r8 = r6
            goto L6c
        L69:
            r8 = r7
        L6a:
            r9 = r8
            r8 = r3
        L6c:
            if (r8 == 0) goto L8d
            java.lang.Object r9 = r9.b
            androidx.work.impl.model.l r9 = (androidx.work.impl.model.l) r9
            r0.j = r5
            r0.k = r8
            r0.n = r4
            com.quizlet.data.interactor.folder.o r2 = new com.quizlet.data.interactor.folder.o
            r2.<init>(r9, r5)
            java.lang.Object r9 = r9.c
            kotlinx.coroutines.y r9 = (kotlinx.coroutines.AbstractC5040y) r9
            java.lang.Object r9 = kotlinx.coroutines.E.J(r9, r2, r0)
            if (r9 != r1) goto L88
            goto L8a
        L88:
            kotlin.Unit r9 = kotlin.Unit.a
        L8a:
            if (r9 != r1) goto L8d
        L8c:
            return r1
        L8d:
            if (r8 == 0) goto L90
            r3 = r6
        L90:
            java.lang.Boolean r8 = java.lang.Boolean.valueOf(r3)
            return r8
        */
        throw new UnsupportedOperationException("Method not decompiled: com.lyft.android.scissors.b.n(java.util.LinkedHashSet, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public void o(Uri uri) {
        e eVar = new e((CropView) this.b);
        CropView cropView = (CropView) eVar.a;
        if (cropView.getWidth() != 0 || cropView.getHeight() != 0) {
            eVar.b(uri);
        } else if (cropView.getViewTreeObserver().isAlive()) {
            cropView.getViewTreeObserver().addOnGlobalLayoutListener(new d(eVar, uri));
        }
    }

    public b(androidx.work.impl.model.l folderOnboardingUseCase) {
        this.a = 16;
        Intrinsics.checkNotNullParameter(folderOnboardingUseCase, "folderOnboardingUseCase");
        this.b = folderOnboardingUseCase;
    }

    public b(com.quizlet.data.repository.activitycenter.b feedRepository) {
        this.a = 4;
        Intrinsics.checkNotNullParameter(feedRepository, "feedRepository");
        this.b = feedRepository;
    }

    public b(com.quizlet.infra.legacysyncengine.net.f mSyncDispatcher) {
        this.a = 29;
        Intrinsics.checkNotNullParameter(mSyncDispatcher, "mSyncDispatcher");
        this.b = mSyncDispatcher;
    }

    public b(com.quizlet.local.datastore.models.metering.i soundEffectsRepository) {
        this.a = 8;
        Intrinsics.checkNotNullParameter(soundEffectsRepository, "soundEffectsRepository");
        this.b = soundEffectsRepository;
    }

    public b(C4567d confirmationWallRepository) {
        this.a = 5;
        Intrinsics.checkNotNullParameter(confirmationWallRepository, "confirmationWallRepository");
        this.b = confirmationWallRepository;
    }

    public b(com.quizlet.remote.model.notes.e notesRepository) {
        this.a = 6;
        Intrinsics.checkNotNullParameter(notesRepository, "notesRepository");
        this.b = notesRepository;
    }

    public b(com.quizlet.data.repository.activitycenter.b activityCenterRepository, androidx.work.impl.model.c dispatcher) {
        this.a = 3;
        Intrinsics.checkNotNullParameter(activityCenterRepository, "activityCenterRepository");
        Intrinsics.checkNotNullParameter(dispatcher, "dispatcher");
        this.b = activityCenterRepository;
    }

    public b(r workManager) {
        this.a = 1;
        Intrinsics.checkNotNullParameter(workManager, "workManager");
        this.b = workManager;
    }

    /* JADX WARN: Code restructure failed: missing block: B:57:0x0214, code lost:
    
        r1.add(new com.quizlet.progress.types.e(r4, r18, r20, r22, r12));
        r3 = r27;
        r2 = r10;
        r13 = r25;
     */
    /* JADX WARN: Removed duplicated region for block: B:157:0x059c  */
    /* JADX WARN: Removed duplicated region for block: B:179:0x05f9  */
    /* JADX WARN: Type inference failed for: r2v18, types: [java.lang.Object, java.util.List] */
    @Override // io.reactivex.rxjava3.functions.h
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object apply(java.lang.Object r27) {
        /*
            Method dump skipped, instructions count: 1962
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.lyft.android.scissors.b.apply(java.lang.Object):java.lang.Object");
    }

    public b(com.quizlet.infra.legacysyncengine.managers.d loggedInUserManager) {
        this.a = 2;
        Intrinsics.checkNotNullParameter(loggedInUserManager, "loggedInUserManager");
        this.b = loggedInUserManager;
    }

    public b(PackageManager packageManager) {
        this.a = 15;
        Intrinsics.checkNotNullParameter(packageManager, "packageManager");
        this.b = packageManager;
    }

    public b(DatabaseHelper database) {
        this.a = 22;
        Intrinsics.checkNotNullParameter(database, "database");
        this.b = kotlin.l.b(new com.quizlet.local.ormlite.database.dao.a(database, 2));
    }

    public b(InterfaceC1076h dataStore) {
        this.a = 21;
        Intrinsics.checkNotNullParameter(dataStore, "dataStore");
        this.b = dataStore;
    }
}
