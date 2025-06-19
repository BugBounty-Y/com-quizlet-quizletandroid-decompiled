package com.quizlet.data.repository.qclass;

import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.Context;
import android.content.SharedPreferences;
import android.graphics.SurfaceTexture;
import android.util.Log;
import android.view.Surface;
import androidx.appcompat.app.L;
import androidx.camera.camera2.internal.C0148z;
import androidx.camera.core.ProcessingException;
import androidx.camera.core.processing.l;
import androidx.compose.foundation.lazy.layout.C0429a;
import androidx.constraintlayout.core.parser.g;
import androidx.paging.V;
import androidx.paging.h1;
import com.comscore.streaming.EventType;
import com.google.android.datatransport.cct.internal.s;
import com.google.android.gms.internal.ads.C3;
import com.google.android.gms.internal.measurement.AbstractC3053s1;
import com.google.android.gms.internal.mlkit_vision_barcode.U;
import com.google.android.gms.internal.mlkit_vision_camera.K1;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3502n4;
import com.google.android.gms.internal.mlkit_vision_common.O4;
import com.google.android.gms.internal.mlkit_vision_common.S3;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3771z;
import com.google.android.gms.tasks.Task;
import com.google.android.gms.tasks.e;
import com.quizlet.billing.manager.f;
import com.quizlet.billing.subscriptions.i;
import com.quizlet.data.repository.metering.j;
import com.quizlet.db.data.caches.UserInfoCache;
import com.quizlet.db.data.models.persisted.DBGroupSet;
import com.quizlet.db.data.models.persisted.DBImage;
import com.quizlet.db.data.models.persisted.DBTerm;
import com.quizlet.quizletandroid.t;
import com.quizlet.quizletandroid.u;
import com.quizlet.quizletandroid.ui.joincontenttofolder.k;
import com.quizlet.quizletandroid.ui.profile.UserFolderListFragment;
import com.quizlet.uicommon.ui.common.widgets.d;
import io.reactivex.rxjava3.core.p;
import io.reactivex.rxjava3.functions.h;
import io.reactivex.rxjava3.internal.operators.completable.m;
import io.reactivex.rxjava3.internal.operators.observable.C4884c;
import io.reactivex.rxjava3.internal.operators.observable.J;
import java.io.Closeable;
import java.io.File;
import java.io.FileWriter;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicReference;
import kotlin.collections.C;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.AbstractC5040y;
import kotlinx.coroutines.flow.C5013v;
import kotlinx.coroutines.flow.InterfaceC4992i;
import kotlinx.coroutines.flow.e0;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class c implements androidx.camera.core.impl.utils.futures.c, h1, e, h, dagger.android.b, d {
    public final /* synthetic */ int a;
    public Object b;
    public Object c;

    public /* synthetic */ c(int i, Object obj, Object obj2) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
    }

    public static NotificationChannel e(String str, int i, String str2, String str3) {
        if ((i & 4) != 0) {
            str3 = null;
        }
        NotificationChannel notificationChannel = new NotificationChannel(str, str2, 3);
        if (str3 != null) {
            notificationChannel.setDescription(str3);
        }
        return notificationChannel;
    }

    public static void o(c cVar, androidx.constraintlayout.compose.c cVar2, float f, int i) {
        if ((i & 2) != 0) {
            f = 0;
        }
        float f2 = 0;
        cVar.getClass();
        int i2 = cVar2.b;
        String str = "top";
        if (i2 != 0) {
            if (i2 != 1) {
                Log.e("CCL", "horizontalAnchorIndexToAnchorName: Unknown horizontal index");
            } else {
                str = "bottom";
            }
        }
        androidx.constraintlayout.core.parser.a aVar = new androidx.constraintlayout.core.parser.a(new char[0]);
        aVar.i(androidx.constraintlayout.core.parser.h.i(cVar2.a.toString()));
        aVar.i(androidx.constraintlayout.core.parser.h.i(str));
        aVar.i(new androidx.constraintlayout.core.parser.e(f));
        aVar.i(new androidx.constraintlayout.core.parser.e(f2));
        ((g) cVar.b).B((String) cVar.c, aVar);
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object a(java.lang.String r11, java.lang.String r12, java.lang.String r13, kotlin.coroutines.jvm.internal.c r14) throws java.lang.Throwable {
        /*
            r10 = this;
            boolean r0 = r14 instanceof com.quizlet.features.settings.data.interactor.a
            if (r0 == 0) goto L13
            r0 = r14
            com.quizlet.features.settings.data.interactor.a r0 = (com.quizlet.features.settings.data.interactor.a) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.features.settings.data.interactor.a r0 = new com.quizlet.features.settings.data.interactor.a
            r0.<init>(r10, r14)
        L18:
            java.lang.Object r14 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L34
            if (r2 != r3) goto L2c
            androidx.glance.appwidget.protobuf.Z.e(r14)
            kotlin.r r14 = (kotlin.r) r14
            java.lang.Object r11 = r14.a
            r5 = r10
            goto L4a
        L2c:
            java.lang.IllegalStateException r11 = new java.lang.IllegalStateException
            java.lang.String r12 = "call to 'resume' before 'invoke' with coroutine"
            r11.<init>(r12)
            throw r11
        L34:
            androidx.glance.appwidget.protobuf.Z.e(r14)
            com.quizlet.features.settings.data.interactor.b r4 = new com.quizlet.features.settings.data.interactor.b
            r9 = 0
            r5 = r10
            r6 = r11
            r7 = r12
            r8 = r13
            r4.<init>(r5, r6, r7, r8, r9)
            r0.l = r3
            java.lang.Object r11 = r10.c(r4, r0)
            if (r11 != r1) goto L4a
            return r1
        L4a:
            kotlin.p r12 = kotlin.r.b
            boolean r12 = r11 instanceof kotlin.q
            if (r12 != 0) goto L52
            kotlin.Unit r11 = kotlin.Unit.a
        L52:
            return r11
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.repository.qclass.c.a(java.lang.String, java.lang.String, java.lang.String, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        p pVarG;
        switch (this.a) {
            case 14:
                String sku = (String) obj;
                Intrinsics.checkNotNullParameter(sku, "it");
                i iVar = (i) this.b;
                f billingManager = iVar.a;
                Intrinsics.checkNotNullParameter(sku, "subscriptionSku");
                Intrinsics.checkNotNullParameter(billingManager, "billingManager");
                com.quizlet.billing.model.b user = (com.quizlet.billing.model.b) this.c;
                Intrinsics.checkNotNullParameter(user, "user");
                m mVarC = iVar.c(sku, user);
                billingManager.getClass();
                Intrinsics.checkNotNullParameter(sku, "sku");
                if (billingManager.g.s() || billingManager.g.r()) {
                    pVarG = billingManager.g.g(new com.android.billingclient.api.m(sku));
                    Intrinsics.checkNotNullExpressionValue(pVarG, "map(...)");
                } else {
                    pVarG = p.f(Boolean.FALSE);
                    Intrinsics.checkNotNullExpressionValue(pVarG, "just(...)");
                }
                m mVar = new m(com.google.android.gms.dynamite.d.b(mVarC, pVarG), new com.quizlet.baserecyclerview.decoration.a(4), null, 2);
                Intrinsics.checkNotNullExpressionValue(mVar, "onErrorReturn(...)");
                return mVar;
            case 18:
                Throwable e = (Throwable) obj;
                Intrinsics.checkNotNullParameter(e, "e");
                ((org.slf4j.b) ((com.quizlet.data.repository.classfolder.e) this.b).d).j((String) this.c, e);
                return p.d(e);
            case EventType.WINDOW_STATE /* 22 */:
                Boolean it2 = (Boolean) obj;
                Intrinsics.checkNotNullParameter(it2, "it");
                List list = (List) this.b;
                Intrinsics.d(list);
                Object obj2 = ((com.quizlet.local.ormlite.models.bookmark.a) this.c).c;
                ArrayList arrayList = new ArrayList(C.q(list, 10));
                Iterator it3 = list.iterator();
                while (it3.hasNext()) {
                    arrayList.add(com.quizlet.shared.usecase.folderstudymaterials.b.p((DBGroupSet) it3.next()));
                }
                return arrayList;
            case EventType.AUDIO /* 23 */:
                Boolean it4 = (Boolean) obj;
                Intrinsics.checkNotNullParameter(it4, "it");
                List list2 = (List) this.b;
                Intrinsics.d(list2);
                return AbstractC3771z.c((com.quizlet.local.ormlite.models.term.a) ((com.quizlet.data.repository.set.f) this.c).c, list2);
            default:
                List<DBTerm> list3 = (List) obj;
                Intrinsics.checkNotNullParameter(list3, "list");
                HashSet hashSet = new HashSet();
                for (DBTerm dBTerm : list3) {
                    DBImage definitionImage = dBTerm.getDefinitionImage();
                    String serverSmallUrl = definitionImage != null ? definitionImage.getServerSmallUrl() : null;
                    DBImage definitionImage2 = dBTerm.getDefinitionImage();
                    String serverMediumUrl = definitionImage2 != null ? definitionImage2.getServerMediumUrl() : null;
                    if (serverSmallUrl != null) {
                        hashSet.add(serverSmallUrl);
                    }
                    if (serverMediumUrl != null) {
                        hashSet.add(serverMediumUrl);
                    }
                }
                List listP0 = CollectionsKt.p0(hashSet, 200);
                com.quizlet.quizletandroid.data.management.a aVar = (com.quizlet.quizletandroid.data.management.a) this.c;
                com.quizlet.qutils.data.offline.d dVar = aVar.b;
                s sVar = (s) this.b;
                return new io.reactivex.rxjava3.internal.operators.maybe.e(s.a(sVar, listP0, dVar, (com.quizlet.quizletandroid.ui.common.images.loading.offline.c) sVar.c).g(new com.quizlet.data.repository.course.membership.c(false, aVar, listP0, hashSet)), 3);
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object b(java.util.List r9, kotlin.coroutines.jvm.internal.c r10) {
        /*
            r8 = this;
            boolean r0 = r10 instanceof com.quizlet.remote.model.folderstudymaterial.a
            if (r0 == 0) goto L13
            r0 = r10
            com.quizlet.remote.model.folderstudymaterial.a r0 = (com.quizlet.remote.model.folderstudymaterial.a) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.quizlet.remote.model.folderstudymaterial.a r0 = new com.quizlet.remote.model.folderstudymaterial.a
            r0.<init>(r8, r10)
        L18:
            java.lang.Object r10 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            if (r2 == 0) goto L35
            if (r2 != r3) goto L2d
            com.quizlet.data.repository.qclass.c r9 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r10)
            kotlin.r r10 = (kotlin.r) r10
            java.lang.Object r10 = r10.a
            goto L76
        L2d:
            java.lang.IllegalStateException r9 = new java.lang.IllegalStateException
            java.lang.String r10 = "call to 'resume' before 'invoke' with coroutine"
            r9.<init>(r10)
            throw r9
        L35:
            androidx.glance.appwidget.protobuf.Z.e(r10)
            java.util.ArrayList r10 = new java.util.ArrayList
            r2 = 10
            int r2 = kotlin.collections.C.q(r9, r2)
            r10.<init>(r2)
            java.util.Iterator r9 = r9.iterator()
        L47:
            boolean r2 = r9.hasNext()
            if (r2 == 0) goto L66
            java.lang.Object r2 = r9.next()
            com.quizlet.data.model.g0 r2 = (com.quizlet.data.model.C4129g0) r2
            com.quizlet.remote.model.folderstudymaterial.FolderStudyMaterialsRequest r4 = new com.quizlet.remote.model.folderstudymaterial.FolderStudyMaterialsRequest
            long r5 = r2.a
            com.quizlet.generated.enums.y1 r7 = r2.c
            int r7 = r7.b()
            java.lang.String r2 = r2.b
            r4.<init>(r7, r5, r2)
            r10.add(r4)
            goto L47
        L66:
            r0.j = r8
            r0.m = r3
            java.lang.Object r9 = r8.b
            com.quizlet.remote.model.folderstudymaterial.j r9 = (com.quizlet.remote.model.folderstudymaterial.j) r9
            java.lang.Object r10 = r9.e(r10, r0)
            if (r10 != r1) goto L75
            return r1
        L75:
            r9 = r8
        L76:
            kotlin.p r0 = kotlin.r.b
            boolean r0 = r10 instanceof kotlin.q
            if (r0 != 0) goto La1
            java.util.List r10 = (java.util.List) r10
            java.lang.Object r9 = r9.c
            com.quizlet.quizletandroid.ui.login.di.a r9 = (com.quizlet.quizletandroid.ui.login.di.a) r9
            java.util.ArrayList r9 = com.google.android.gms.internal.mlkit_vision_barcode.S.f(r9, r10)
            java.util.ArrayList r10 = new java.util.ArrayList
            r10.<init>()
            java.util.Iterator r9 = r9.iterator()
        L8f:
            boolean r0 = r9.hasNext()
            if (r0 == 0) goto La1
            java.lang.Object r0 = r9.next()
            boolean r1 = r0 instanceof com.quizlet.data.model.CreatedFolderStudyMaterial
            if (r1 == 0) goto L8f
            r10.add(r0)
            goto L8f
        La1:
            return r10
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.repository.qclass.c.b(java.util.List, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object c(kotlin.jvm.functions.Function1 r5, kotlin.coroutines.jvm.internal.c r6) throws java.lang.Throwable {
        /*
            r4 = this;
            boolean r0 = r6 instanceof com.quizlet.features.settings.data.interactor.c
            if (r0 == 0) goto L13
            r0 = r6
            com.quizlet.features.settings.data.interactor.c r0 = (com.quizlet.features.settings.data.interactor.c) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.features.settings.data.interactor.c r0 = new com.quizlet.features.settings.data.interactor.c
            r0.<init>(r4, r6)
        L18:
            java.lang.Object r6 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L2f
            if (r2 != r3) goto L27
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L45
        L27:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L2f:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            com.quizlet.features.settings.data.interactor.e r6 = new com.quizlet.features.settings.data.interactor.e
            r2 = 0
            r6.<init>(r5, r2)
            r0.l = r3
            java.lang.Object r5 = r4.c
            kotlinx.coroutines.y r5 = (kotlinx.coroutines.AbstractC5040y) r5
            java.lang.Object r6 = kotlinx.coroutines.E.J(r5, r6, r0)
            if (r6 != r1) goto L45
            return r1
        L45:
            kotlin.r r6 = (kotlin.r) r6
            java.lang.Object r5 = r6.a
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.repository.qclass.c.c(kotlin.jvm.functions.Function1, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    @Override // dagger.android.b
    public void d(Object obj) {
        UserFolderListFragment userFolderListFragment = (UserFolderListFragment) obj;
        u uVar = (u) this.b;
        userFolderListFragment.a = uVar.w();
        userFolderListFragment.b = uVar.S0();
        t tVar = uVar.e1;
        com.google.firebase.perf.injection.modules.b bVar = (com.google.firebase.perf.injection.modules.b) this.c;
        AbstractC3502n4.h(k.class, tVar);
        userFolderListFragment.s = new com.onetrust.otpublishers.headless.UI.viewmodel.c(com.google.common.collect.C.d(2, new Object[]{k.class, tVar, com.quizlet.quizletandroid.ui.profile.data.c.class, bVar}, null));
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object f(java.lang.String r5, java.lang.String r6, kotlin.coroutines.jvm.internal.c r7) throws java.lang.Throwable {
        /*
            r4 = this;
            boolean r0 = r7 instanceof com.quizlet.features.settings.data.interactor.f
            if (r0 == 0) goto L13
            r0 = r7
            com.quizlet.features.settings.data.interactor.f r0 = (com.quizlet.features.settings.data.interactor.f) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.features.settings.data.interactor.f r0 = new com.quizlet.features.settings.data.interactor.f
            r0.<init>(r4, r7)
        L18:
            java.lang.Object r7 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L33
            if (r2 != r3) goto L2b
            androidx.glance.appwidget.protobuf.Z.e(r7)
            kotlin.r r7 = (kotlin.r) r7
            java.lang.Object r5 = r7.a
            goto L45
        L2b:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L33:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            com.quizlet.features.settings.data.interactor.g r7 = new com.quizlet.features.settings.data.interactor.g
            r2 = 0
            r7.<init>(r4, r5, r6, r2)
            r0.l = r3
            java.lang.Object r5 = r4.c(r7, r0)
            if (r5 != r1) goto L45
            return r1
        L45:
            kotlin.p r6 = kotlin.r.b
            boolean r6 = r5 instanceof kotlin.q
            if (r6 != 0) goto L4d
            kotlin.Unit r5 = kotlin.Unit.a
        L4d:
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.repository.qclass.c.f(java.lang.String, java.lang.String, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r10v8, types: [org.json.JSONObject] */
    /* JADX WARN: Type inference failed for: r2v1, types: [com.google.firebase.crashlytics.internal.settings.b] */
    /* JADX WARN: Type inference failed for: r3v0, types: [long] */
    /* JADX WARN: Type inference failed for: r3v1 */
    /* JADX WARN: Type inference failed for: r3v10 */
    /* JADX WARN: Type inference failed for: r3v11 */
    /* JADX WARN: Type inference failed for: r3v4, types: [java.io.Closeable] */
    @Override // com.google.android.gms.tasks.e
    public Task g(Object obj) throws Throwable {
        FileWriter fileWriter;
        ?? r10 = (JSONObject) ((com.google.firebase.crashlytics.internal.concurrency.d) this.b).c.a.submit(new androidx.work.impl.utils.d(this, 5)).get();
        Closeable closeable = null;
        if (r10 != 0) {
            s sVar = (s) this.c;
            com.google.firebase.crashlytics.internal.settings.a aVarI = ((com.google.firebase.crashlytics.internal.settings.b) sVar.d).i(r10);
            ?? r3 = aVarI.c;
            L l = (L) sVar.f;
            l.getClass();
            Log.isLoggable("FirebaseCrashlytics", 2);
            try {
            } catch (Throwable th) {
                th = th;
                closeable = r3;
            }
            try {
                try {
                    r10.put("expires_at", r3);
                    try {
                        fileWriter = new FileWriter((File) l.b);
                    } catch (Exception e) {
                        e = e;
                        fileWriter = null;
                        Log.e("FirebaseCrashlytics", "Failed to cache settings", e);
                        r3 = fileWriter;
                        com.google.firebase.crashlytics.internal.common.f.b(r3, "Failed to close settings writer.");
                        r10.toString();
                        Log.isLoggable("FirebaseCrashlytics", 3);
                        String str = ((com.google.firebase.crashlytics.internal.settings.d) sVar.c).f;
                        SharedPreferences.Editor editorEdit = ((Context) sVar.b).getSharedPreferences("com.google.firebase.crashlytics", 0).edit();
                        editorEdit.putString("existing_instance_identifier", str);
                        editorEdit.apply();
                        ((AtomicReference) sVar.h).set(aVarI);
                        ((com.google.android.gms.tasks.f) ((AtomicReference) sVar.i).get()).d(aVarI);
                        return S3.i(null);
                    }
                } catch (Exception e2) {
                    e = e2;
                }
                try {
                    fileWriter.write(r10.toString());
                    fileWriter.flush();
                    r3 = fileWriter;
                } catch (Exception e3) {
                    e = e3;
                    Log.e("FirebaseCrashlytics", "Failed to cache settings", e);
                    r3 = fileWriter;
                    com.google.firebase.crashlytics.internal.common.f.b(r3, "Failed to close settings writer.");
                    r10.toString();
                    Log.isLoggable("FirebaseCrashlytics", 3);
                    String str2 = ((com.google.firebase.crashlytics.internal.settings.d) sVar.c).f;
                    SharedPreferences.Editor editorEdit2 = ((Context) sVar.b).getSharedPreferences("com.google.firebase.crashlytics", 0).edit();
                    editorEdit2.putString("existing_instance_identifier", str2);
                    editorEdit2.apply();
                    ((AtomicReference) sVar.h).set(aVarI);
                    ((com.google.android.gms.tasks.f) ((AtomicReference) sVar.i).get()).d(aVarI);
                    return S3.i(null);
                }
                com.google.firebase.crashlytics.internal.common.f.b(r3, "Failed to close settings writer.");
                r10.toString();
                Log.isLoggable("FirebaseCrashlytics", 3);
                String str22 = ((com.google.firebase.crashlytics.internal.settings.d) sVar.c).f;
                SharedPreferences.Editor editorEdit22 = ((Context) sVar.b).getSharedPreferences("com.google.firebase.crashlytics", 0).edit();
                editorEdit22.putString("existing_instance_identifier", str22);
                editorEdit22.apply();
                ((AtomicReference) sVar.h).set(aVarI);
                ((com.google.android.gms.tasks.f) ((AtomicReference) sVar.i).get()).d(aVarI);
            } catch (Throwable th2) {
                th = th2;
                com.google.firebase.crashlytics.internal.common.f.b(closeable, "Failed to close settings writer.");
                throw th;
            }
        }
        return S3.i(null);
    }

    /* JADX WARN: Removed duplicated region for block: B:8:0x0014  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object h(java.lang.String r11, java.lang.String r12, java.lang.String r13, java.lang.String r14, kotlin.coroutines.jvm.internal.c r15) throws java.lang.Throwable {
        /*
            r10 = this;
            boolean r2 = r15 instanceof com.quizlet.features.settings.data.interactor.h
            if (r2 == 0) goto L14
            r2 = r15
            com.quizlet.features.settings.data.interactor.h r2 = (com.quizlet.features.settings.data.interactor.h) r2
            int r3 = r2.l
            r4 = -2147483648(0xffffffff80000000, float:-0.0)
            r5 = r3 & r4
            if (r5 == 0) goto L14
            int r3 = r3 - r4
            r2.l = r3
        L12:
            r7 = r2
            goto L1a
        L14:
            com.quizlet.features.settings.data.interactor.h r2 = new com.quizlet.features.settings.data.interactor.h
            r2.<init>(r10, r15)
            goto L12
        L1a:
            java.lang.Object r0 = r7.j
            kotlin.coroutines.intrinsics.a r8 = kotlin.coroutines.intrinsics.a.a
            int r2 = r7.l
            r9 = 1
            if (r2 == 0) goto L35
            if (r2 != r9) goto L2d
            androidx.glance.appwidget.protobuf.Z.e(r0)
            kotlin.r r0 = (kotlin.r) r0
            java.lang.Object r0 = r0.a
            goto L4c
        L2d:
            java.lang.IllegalStateException r0 = new java.lang.IllegalStateException
            java.lang.String r2 = "call to 'resume' before 'invoke' with coroutine"
            r0.<init>(r2)
            throw r0
        L35:
            androidx.glance.appwidget.protobuf.Z.e(r0)
            com.quizlet.features.settings.data.interactor.i r0 = new com.quizlet.features.settings.data.interactor.i
            r6 = 0
            r1 = r10
            r2 = r11
            r3 = r12
            r4 = r13
            r5 = r14
            r0.<init>(r1, r2, r3, r4, r5, r6)
            r7.l = r9
            java.lang.Object r0 = r10.c(r0, r7)
            if (r0 != r8) goto L4c
            return r8
        L4c:
            kotlin.p r2 = kotlin.r.b
            boolean r2 = r0 instanceof kotlin.q
            if (r2 != 0) goto L54
            kotlin.Unit r0 = kotlin.Unit.a
        L54:
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.repository.qclass.c.h(java.lang.String, java.lang.String, java.lang.String, java.lang.String, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object i(java.lang.String r5, java.lang.String r6, kotlin.coroutines.jvm.internal.c r7) throws java.lang.Throwable {
        /*
            r4 = this;
            boolean r0 = r7 instanceof com.quizlet.features.settings.data.interactor.j
            if (r0 == 0) goto L13
            r0 = r7
            com.quizlet.features.settings.data.interactor.j r0 = (com.quizlet.features.settings.data.interactor.j) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.features.settings.data.interactor.j r0 = new com.quizlet.features.settings.data.interactor.j
            r0.<init>(r4, r7)
        L18:
            java.lang.Object r7 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L33
            if (r2 != r3) goto L2b
            androidx.glance.appwidget.protobuf.Z.e(r7)
            kotlin.r r7 = (kotlin.r) r7
            java.lang.Object r5 = r7.a
            goto L45
        L2b:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L33:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            com.quizlet.features.settings.data.interactor.k r7 = new com.quizlet.features.settings.data.interactor.k
            r2 = 0
            r7.<init>(r4, r5, r6, r2)
            r0.l = r3
            java.lang.Object r5 = r4.c(r7, r0)
            if (r5 != r1) goto L45
            return r1
        L45:
            kotlin.p r6 = kotlin.r.b
            boolean r6 = r5 instanceof kotlin.q
            if (r6 != 0) goto L4d
            kotlin.Unit r5 = kotlin.Unit.a
        L4d:
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.repository.qclass.c.i(java.lang.String, java.lang.String, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object j(java.util.List r9, kotlin.coroutines.jvm.internal.c r10) {
        /*
            r8 = this;
            boolean r0 = r10 instanceof com.quizlet.remote.model.folderstudymaterial.b
            if (r0 == 0) goto L13
            r0 = r10
            com.quizlet.remote.model.folderstudymaterial.b r0 = (com.quizlet.remote.model.folderstudymaterial.b) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.quizlet.remote.model.folderstudymaterial.b r0 = new com.quizlet.remote.model.folderstudymaterial.b
            r0.<init>(r8, r10)
        L18:
            java.lang.Object r10 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            if (r2 == 0) goto L35
            if (r2 != r3) goto L2d
            com.quizlet.data.repository.qclass.c r9 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r10)
            kotlin.r r10 = (kotlin.r) r10
            java.lang.Object r10 = r10.a
            goto L76
        L2d:
            java.lang.IllegalStateException r9 = new java.lang.IllegalStateException
            java.lang.String r10 = "call to 'resume' before 'invoke' with coroutine"
            r9.<init>(r10)
            throw r9
        L35:
            androidx.glance.appwidget.protobuf.Z.e(r10)
            java.util.ArrayList r10 = new java.util.ArrayList
            r2 = 10
            int r2 = kotlin.collections.C.q(r9, r2)
            r10.<init>(r2)
            java.util.Iterator r9 = r9.iterator()
        L47:
            boolean r2 = r9.hasNext()
            if (r2 == 0) goto L66
            java.lang.Object r2 = r9.next()
            com.quizlet.data.model.g0 r2 = (com.quizlet.data.model.C4129g0) r2
            com.quizlet.remote.model.folderstudymaterial.FolderStudyMaterialsRequest r4 = new com.quizlet.remote.model.folderstudymaterial.FolderStudyMaterialsRequest
            long r5 = r2.a
            com.quizlet.generated.enums.y1 r7 = r2.c
            int r7 = r7.b()
            java.lang.String r2 = r2.b
            r4.<init>(r7, r5, r2)
            r10.add(r4)
            goto L47
        L66:
            r0.j = r8
            r0.m = r3
            java.lang.Object r9 = r8.b
            com.quizlet.remote.model.folderstudymaterial.j r9 = (com.quizlet.remote.model.folderstudymaterial.j) r9
            java.lang.Object r10 = r9.a(r10, r0)
            if (r10 != r1) goto L75
            return r1
        L75:
            r9 = r8
        L76:
            kotlin.p r0 = kotlin.r.b
            boolean r0 = r10 instanceof kotlin.q
            if (r0 != 0) goto La1
            java.util.List r10 = (java.util.List) r10
            java.lang.Object r9 = r9.c
            com.quizlet.quizletandroid.ui.login.di.a r9 = (com.quizlet.quizletandroid.ui.login.di.a) r9
            java.util.ArrayList r9 = com.google.android.gms.internal.mlkit_vision_barcode.S.f(r9, r10)
            java.util.ArrayList r10 = new java.util.ArrayList
            r10.<init>()
            java.util.Iterator r9 = r9.iterator()
        L8f:
            boolean r0 = r9.hasNext()
            if (r0 == 0) goto La1
            java.lang.Object r0 = r9.next()
            boolean r1 = r0 instanceof com.quizlet.data.model.DeletedFolderStudyMaterial
            if (r1 == 0) goto L8f
            r10.add(r0)
            goto L8f
        La1:
            return r10
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.repository.qclass.c.j(java.util.List, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public InterfaceC4992i k(long j) {
        j jVar = (j) this.b;
        com.quizlet.features.infra.studysetting.datasource.a aVar = (com.quizlet.features.infra.studysetting.datasource.a) jVar.c;
        if (aVar == null) {
            aVar = new com.quizlet.features.infra.studysetting.datasource.a((com.quizlet.infra.legacysyncengine.net.c) ((com.google.mlkit.vision.documentscanner.internal.c) jVar.a).b, j, 7);
            jVar.c = aVar;
        }
        J jQ = aVar.f().l(new C0429a(j)).q(com.quizlet.quizletandroid.ui.setpage.terms.diagrams.data.b.b);
        Intrinsics.checkNotNullExpressionValue(jQ, "map(...)");
        aVar.d();
        com.quizlet.features.infra.studysetting.datasource.a aVar2 = (com.quizlet.features.infra.studysetting.datasource.a) jVar.d;
        if (aVar2 == null) {
            aVar2 = new com.quizlet.features.infra.studysetting.datasource.a(((com.quizlet.infra.legacysyncengine.datasources.d) jVar.b).a, j, 5);
            jVar.d = aVar2;
        }
        C4884c c4884cL = aVar2.f().l(com.quizlet.quizletandroid.ui.setpage.terms.diagrams.data.b.a);
        Intrinsics.checkNotNullExpressionValue(c4884cL, "filter(...)");
        aVar2.d();
        io.reactivex.rxjava3.core.i iVarD = io.reactivex.rxjava3.core.i.d(jQ, c4884cL, new com.quizlet.quizletandroid.ui.setpage.terms.diagrams.data.a(j));
        Intrinsics.checkNotNullExpressionValue(iVarD, "combineLatest(...)");
        return e0.s(new C5013v(K1.f(iVarD), new androidx.activity.compose.p(jVar, (kotlin.coroutines.h) null, 4)), (AbstractC5040y) this.c);
    }

    public String l(com.bumptech.glide.load.e eVar) {
        String str;
        synchronized (((C0148z) this.b)) {
            str = (String) ((C0148z) this.b).a(eVar);
        }
        if (str == null) {
            com.bumptech.glide.load.engine.cache.g gVar = (com.bumptech.glide.load.engine.cache.g) ((com.quizlet.data.repository.course.membership.c) this.c).a();
            try {
                eVar.a(gVar.a);
                byte[] bArrDigest = gVar.a.digest();
                char[] cArr = com.bumptech.glide.util.m.b;
                synchronized (cArr) {
                    for (int i = 0; i < bArrDigest.length; i++) {
                        byte b = bArrDigest[i];
                        int i2 = i * 2;
                        char[] cArr2 = com.bumptech.glide.util.m.a;
                        cArr[i2] = cArr2[(b & 255) >>> 4];
                        cArr[i2 + 1] = cArr2[b & 15];
                    }
                    str = new String(cArr);
                }
            } finally {
                ((com.quizlet.data.repository.course.membership.c) this.c).o(gVar);
            }
        }
        synchronized (((C0148z) this.b)) {
            ((C0148z) this.b).f(eVar, str);
        }
        return str;
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object m(kotlin.coroutines.jvm.internal.c r5) throws com.quizlet.data.repository.school.exceptions.SchoolMembershipException {
        /*
            r4 = this;
            boolean r0 = r5 instanceof com.quizlet.data.interactor.school.h
            if (r0 == 0) goto L13
            r0 = r5
            com.quizlet.data.interactor.school.h r0 = (com.quizlet.data.interactor.school.h) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.quizlet.data.interactor.school.h r0 = new com.quizlet.data.interactor.school.h
            r0.<init>(r4, r5)
        L18:
            java.lang.Object r5 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            if (r2 == 0) goto L33
            if (r2 != r3) goto L2b
            com.quizlet.data.repository.qclass.c r0 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r5)     // Catch: java.lang.Exception -> L29
            goto L66
        L29:
            r5 = move-exception
            goto L71
        L2b:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r0)
            throw r5
        L33:
            androidx.glance.appwidget.protobuf.Z.e(r5)
            java.lang.Object r5 = r4.b     // Catch: java.lang.Exception -> L6f
            com.quizlet.data.repository.school.membership.a r5 = (com.quizlet.data.repository.school.membership.a) r5     // Catch: java.lang.Exception -> L6f
            r0.j = r4     // Catch: java.lang.Exception -> L6f
            r0.m = r3     // Catch: java.lang.Exception -> L6f
            java.lang.Object r5 = r5.b     // Catch: java.lang.Exception -> L6f
            com.quizlet.remote.model.school.h r5 = (com.quizlet.remote.model.school.h) r5     // Catch: java.lang.Exception -> L6f
            com.quizlet.remote.model.school.g r2 = new com.quizlet.remote.model.school.g     // Catch: java.lang.Exception -> L6f
            r3 = 0
            r2.<init>(r5, r3)     // Catch: java.lang.Exception -> L6f
            java.lang.Object r5 = r5.b     // Catch: java.lang.Exception -> L6f
            kotlinx.coroutines.y r5 = (kotlinx.coroutines.AbstractC5040y) r5     // Catch: java.lang.Exception -> L6f
            io.reactivex.rxjava3.internal.operators.flowable.b r5 = com.google.android.gms.internal.mlkit_vision_camera.L1.e(r5, r2)     // Catch: java.lang.Exception -> L6f
            com.quizlet.quizletandroid.ui.common.images.capture.a r2 = new com.quizlet.quizletandroid.ui.common.images.capture.a     // Catch: java.lang.Exception -> L6f
            r2.<init>()     // Catch: java.lang.Exception -> L6f
            io.reactivex.rxjava3.internal.operators.single.g r5 = r5.e(r2)     // Catch: java.lang.Exception -> L6f
            java.lang.String r2 = "flatMap(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r5, r2)     // Catch: java.lang.Exception -> L6f
            java.lang.Object r5 = com.google.android.gms.internal.mlkit_vision_camera.I1.b(r5, r0)     // Catch: java.lang.Exception -> L6f
            if (r5 != r1) goto L65
            return r1
        L65:
            r0 = r4
        L66:
            java.util.List r5 = (java.util.List) r5     // Catch: java.lang.Exception -> L29
            java.lang.Object r5 = kotlin.collections.CollectionsKt.firstOrNull(r5)     // Catch: java.lang.Exception -> L29
            return r5
        L6d:
            r0 = r4
            goto L71
        L6f:
            r5 = move-exception
            goto L6d
        L71:
            java.lang.Object r0 = r0.c
            org.slf4j.b r0 = (org.slf4j.b) r0
            java.lang.String r1 = "Error retrieving users school membership"
            r0.m(r1)
            com.quizlet.data.repository.school.exceptions.SchoolMembershipException r0 = new com.quizlet.data.repository.school.exceptions.SchoolMembershipException
            java.lang.String r1 = "Could not get users school membership"
            java.lang.String r2 = "message"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r1, r2)
            java.lang.String r2 = "cause"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r5, r2)
            r0.<init>(r1, r5)
            throw r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.repository.qclass.c.m(kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object n(long r11, java.lang.String r13, kotlin.coroutines.jvm.internal.c r14) throws java.lang.Throwable {
        /*
            r10 = this;
            boolean r0 = r14 instanceof com.quizlet.data.interactor.folder.u
            if (r0 == 0) goto L13
            r0 = r14
            com.quizlet.data.interactor.folder.u r0 = (com.quizlet.data.interactor.folder.u) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.data.interactor.folder.u r0 = new com.quizlet.data.interactor.folder.u
            r0.<init>(r10, r14)
        L18:
            java.lang.Object r14 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L30
            if (r2 != r3) goto L28
            androidx.glance.appwidget.protobuf.Z.e(r14)
            r5 = r10
            goto L49
        L28:
            java.lang.IllegalStateException r11 = new java.lang.IllegalStateException
            java.lang.String r12 = "call to 'resume' before 'invoke' with coroutine"
            r11.<init>(r12)
            throw r11
        L30:
            androidx.glance.appwidget.protobuf.Z.e(r14)
            com.quizlet.data.interactor.folder.v r4 = new com.quizlet.data.interactor.folder.v
            r9 = 0
            r5 = r10
            r6 = r11
            r8 = r13
            r4.<init>(r5, r6, r8, r9)
            r0.l = r3
            java.lang.Object r11 = r5.c
            kotlinx.coroutines.y r11 = (kotlinx.coroutines.AbstractC5040y) r11
            java.lang.Object r14 = kotlinx.coroutines.E.J(r11, r4, r0)
            if (r14 != r1) goto L49
            return r1
        L49:
            java.lang.String r11 = "withContext(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r14, r11)
            return r14
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.repository.qclass.c.n(long, java.lang.String, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    @Override // androidx.camera.core.impl.utils.futures.c
    public void onFailure(Throwable th) {
        switch (this.a) {
            case 1:
                throw new IllegalStateException("Future should never fail. Did it get completed by GC?", th);
            default:
                int i = ((androidx.camera.core.processing.k) this.b).f;
                if (i == 2 && (th instanceof CancellationException)) {
                    AbstractC3053s1.f(3, "DualSurfaceProcessorNode");
                    return;
                }
                AbstractC3053s1.i("DualSurfaceProcessorNode", "Downstream node failed to provide Surface. Target: " + U.b(i), th);
                return;
        }
    }

    @Override // androidx.camera.core.impl.utils.futures.c, io.reactivex.rxjava3.core.q, com.google.android.gms.tasks.d
    public void onSuccess(Object obj) {
        switch (this.a) {
            case 1:
                ((Surface) this.b).release();
                ((SurfaceTexture) this.c).release();
                break;
            default:
                l lVar = (l) obj;
                lVar.getClass();
                try {
                    ((androidx.camera.core.processing.m) ((com.quizlet.data.repository.folderwithcreatorinclass.e) this.c).a).b(lVar);
                    break;
                } catch (ProcessingException e) {
                    AbstractC3053s1.d("DualSurfaceProcessorNode", "Failed to send SurfaceOutput to SurfaceProcessor.", e);
                }
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object p(java.lang.String r5, kotlin.coroutines.jvm.internal.c r6) throws java.lang.Throwable {
        /*
            r4 = this;
            boolean r0 = r6 instanceof com.quizlet.features.settings.data.interactor.l
            if (r0 == 0) goto L13
            r0 = r6
            com.quizlet.features.settings.data.interactor.l r0 = (com.quizlet.features.settings.data.interactor.l) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.features.settings.data.interactor.l r0 = new com.quizlet.features.settings.data.interactor.l
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
            com.quizlet.features.settings.data.interactor.m r6 = new com.quizlet.features.settings.data.interactor.m
            r2 = 0
            r6.<init>(r4, r5, r2)
            r0.l = r3
            java.lang.Object r5 = r4.c(r6, r0)
            if (r5 != r1) goto L45
            return r1
        L45:
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.repository.qclass.c.p(java.lang.String, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object q(java.lang.String r5, kotlin.coroutines.jvm.internal.c r6) throws java.lang.Throwable {
        /*
            r4 = this;
            boolean r0 = r6 instanceof com.quizlet.features.settings.data.interactor.n
            if (r0 == 0) goto L13
            r0 = r6
            com.quizlet.features.settings.data.interactor.n r0 = (com.quizlet.features.settings.data.interactor.n) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.features.settings.data.interactor.n r0 = new com.quizlet.features.settings.data.interactor.n
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
            com.quizlet.features.settings.data.interactor.o r6 = new com.quizlet.features.settings.data.interactor.o
            r2 = 0
            r6.<init>(r4, r5, r2)
            r0.l = r3
            java.lang.Object r5 = r4.c(r6, r0)
            if (r5 != r1) goto L45
            return r1
        L45:
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.repository.qclass.c.q(java.lang.String, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object r(java.lang.String r5, kotlin.coroutines.jvm.internal.c r6) throws java.lang.Throwable {
        /*
            r4 = this;
            boolean r0 = r6 instanceof com.quizlet.features.settings.data.interactor.p
            if (r0 == 0) goto L13
            r0 = r6
            com.quizlet.features.settings.data.interactor.p r0 = (com.quizlet.features.settings.data.interactor.p) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.features.settings.data.interactor.p r0 = new com.quizlet.features.settings.data.interactor.p
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
            com.quizlet.features.settings.data.interactor.q r6 = new com.quizlet.features.settings.data.interactor.q
            r2 = 0
            r6.<init>(r4, r5, r2)
            r0.l = r3
            java.lang.Object r5 = r4.c(r6, r0)
            if (r5 != r1) goto L45
            return r1
        L45:
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.repository.qclass.c.r(java.lang.String, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:8:0x0014  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object s(java.lang.String r11, java.lang.String r12, java.lang.Integer r13, int r14, kotlin.coroutines.jvm.internal.c r15) throws java.lang.Throwable {
        /*
            r10 = this;
            boolean r2 = r15 instanceof com.quizlet.data.repository.qclass.a
            if (r2 == 0) goto L14
            r2 = r15
            com.quizlet.data.repository.qclass.a r2 = (com.quizlet.data.repository.qclass.a) r2
            int r3 = r2.l
            r4 = -2147483648(0xffffffff80000000, float:-0.0)
            r5 = r3 & r4
            if (r5 == 0) goto L14
            int r3 = r3 - r4
            r2.l = r3
        L12:
            r7 = r2
            goto L1a
        L14:
            com.quizlet.data.repository.qclass.a r2 = new com.quizlet.data.repository.qclass.a
            r2.<init>(r10, r15)
            goto L12
        L1a:
            java.lang.Object r0 = r7.j
            kotlin.coroutines.intrinsics.a r8 = kotlin.coroutines.intrinsics.a.a
            int r2 = r7.l
            r9 = 1
            if (r2 == 0) goto L31
            if (r2 != r9) goto L29
            androidx.glance.appwidget.protobuf.Z.e(r0)
            goto L4c
        L29:
            java.lang.IllegalStateException r0 = new java.lang.IllegalStateException
            java.lang.String r2 = "call to 'resume' before 'invoke' with coroutine"
            r0.<init>(r2)
            throw r0
        L31:
            androidx.glance.appwidget.protobuf.Z.e(r0)
            com.quizlet.data.repository.qclass.b r0 = new com.quizlet.data.repository.qclass.b
            r6 = 0
            r1 = r10
            r2 = r11
            r3 = r12
            r4 = r13
            r5 = r14
            r0.<init>(r1, r2, r3, r4, r5, r6)
            r7.l = r9
            java.lang.Object r2 = r10.c
            kotlinx.coroutines.y r2 = (kotlinx.coroutines.AbstractC5040y) r2
            java.lang.Object r0 = kotlinx.coroutines.E.J(r2, r0, r7)
            if (r0 != r8) goto L4c
            return r8
        L4c:
            java.lang.String r2 = "withContext(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r0, r2)
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.repository.qclass.c.s(java.lang.String, java.lang.String, java.lang.Integer, int, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public c(com.quizlet.data.repository.folderset.c cVar, byte b) {
        this.a = 13;
        this.c = cVar;
    }

    public /* synthetic */ c(Object obj, boolean z, Object obj2, int i) {
        this.a = i;
        this.c = obj;
        this.b = obj2;
    }

    public c(com.quizlet.data.repository.folderset.c cVar) {
        this.a = 10;
        this.c = new C3();
        this.b = cVar;
        O4.b();
    }

    public c(j repository, AbstractC5040y ioDispatcher) {
        this.a = 19;
        Intrinsics.checkNotNullParameter(repository, "repository");
        Intrinsics.checkNotNullParameter(ioDispatcher, "ioDispatcher");
        this.b = repository;
        this.c = ioDispatcher;
    }

    public c(com.quizlet.remote.model.folderstudymaterial.j dataSource, com.quizlet.quizletandroid.ui.login.di.a responseMapper) {
        this.a = 29;
        Intrinsics.checkNotNullParameter(dataSource, "dataSource");
        Intrinsics.checkNotNullParameter(responseMapper, "responseMapper");
        this.b = dataSource;
        this.c = responseMapper;
    }

    public c(com.quizlet.data.repository.school.membership.a schoolMembershipRepository, androidx.work.impl.model.c dispatcher, org.slf4j.b logger) {
        this.a = 17;
        Intrinsics.checkNotNullParameter(schoolMembershipRepository, "schoolMembershipRepository");
        Intrinsics.checkNotNullParameter(dispatcher, "dispatcher");
        Intrinsics.checkNotNullParameter(logger, "logger");
        this.b = schoolMembershipRepository;
        this.c = logger;
    }

    public c(com.quizlet.data.repository.explanations.question.a repository, androidx.work.impl.model.c dispatcher) {
        this.a = 15;
        Intrinsics.checkNotNullParameter(repository, "repository");
        Intrinsics.checkNotNullParameter(dispatcher, "dispatcher");
        this.b = repository;
        this.c = dispatcher;
    }

    public c(com.quizlet.data.repository.folder.i folderRepository, AbstractC5040y ioDispatcher) {
        this.a = 16;
        Intrinsics.checkNotNullParameter(folderRepository, "folderRepository");
        Intrinsics.checkNotNullParameter(ioDispatcher, "ioDispatcher");
        this.b = folderRepository;
        this.c = ioDispatcher;
    }

    public c(NotificationManager notificationManager, Context context) {
        this.a = 28;
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(notificationManager, "notificationManager");
        this.b = context;
        this.c = notificationManager;
    }

    public c(com.google.firebase.messaging.u remoteDataSource, com.quizlet.data.connectivity.a networkStatus, org.slf4j.b logger, AbstractC5040y dispatcher) {
        this.a = 0;
        Intrinsics.checkNotNullParameter(remoteDataSource, "remoteDataSource");
        Intrinsics.checkNotNullParameter(networkStatus, "networkStatus");
        Intrinsics.checkNotNullParameter(logger, "logger");
        Intrinsics.checkNotNullParameter(dispatcher, "dispatcher");
        this.b = remoteDataSource;
        this.c = dispatcher;
    }

    public c(com.quizlet.quizletandroid.ui.usersettings.d userSettingsApi, AbstractC5040y dispatcher) {
        this.a = 21;
        Intrinsics.checkNotNullParameter(userSettingsApi, "userSettingsApi");
        Intrinsics.checkNotNullParameter(dispatcher, "dispatcher");
        this.b = userSettingsApi;
        this.c = dispatcher;
    }

    public c() {
        this.a = 7;
        this.b = new C0148z(1, 1000L);
        this.c = com.bumptech.glide.util.pool.d.a(10, new com.onetrust.otpublishers.headless.Internal.Helper.h(6));
    }

    public c(SharedPreferences sharedPreferences, UserInfoCache userInfoCache) {
        this.a = 20;
        Intrinsics.checkNotNullParameter(sharedPreferences, "sharedPreferences");
        Intrinsics.checkNotNullParameter(userInfoCache, "userInfoCache");
        this.b = sharedPreferences;
        this.c = userInfoCache;
    }

    public c(int i, g gVar) {
        this.a = 4;
        this.b = gVar;
        String str = "top";
        if (i != 0) {
            if (i != 1) {
                Log.e("CCL", "horizontalAnchorIndexToAnchorName: Unknown horizontal index");
            } else {
                str = "bottom";
            }
        }
        this.c = str;
    }

    public c(V v, com.quizlet.data.repository.explanations.myexplanations.a retryEventBus) {
        this.a = 5;
        Intrinsics.checkNotNullParameter(retryEventBus, "retryEventBus");
        this.c = v;
        this.b = retryEventBus;
    }

    public c(u uVar) {
        this.a = 24;
        this.b = uVar;
        this.c = new com.google.firebase.perf.injection.modules.b(uVar, 4);
    }
}
