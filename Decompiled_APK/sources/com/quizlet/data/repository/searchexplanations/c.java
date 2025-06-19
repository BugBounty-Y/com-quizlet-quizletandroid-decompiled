package com.quizlet.data.repository.searchexplanations;

import android.content.Context;
import android.content.SharedPreferences;
import android.graphics.drawable.BitmapDrawable;
import android.hardware.camera2.CameraCaptureSession;
import android.hardware.camera2.CaptureRequest;
import android.os.SystemClock;
import android.util.Log;
import android.view.View;
import androidx.camera.camera2.internal.C0135l;
import androidx.camera.core.C0194q;
import androidx.compose.foundation.gestures.l1;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.E;
import androidx.compose.ui.node.V;
import androidx.compose.ui.node.e0;
import androidx.compose.ui.node.r0;
import androidx.constraintlayout.compose.d;
import androidx.constraintlayout.core.parser.e;
import androidx.constraintlayout.core.parser.g;
import androidx.core.view.D0;
import androidx.core.view.InterfaceC1062t;
import androidx.recyclerview.widget.C1372j;
import androidx.work.impl.WorkDatabase_Impl;
import androidx.work.impl.model.n;
import com.braze.support.u;
import com.bumptech.glide.load.engine.v;
import com.bumptech.glide.load.k;
import com.bumptech.glide.load.resource.bitmap.C1539b;
import com.bumptech.glide.load.resource.bitmap.C1541d;
import com.comscore.streaming.EventType;
import com.google.android.datatransport.cct.internal.s;
import com.google.android.gms.common.internal.MethodInvocation;
import com.google.android.gms.common.internal.TelemetryData;
import com.google.android.gms.internal.mlkit_vision_barcode.W4;
import com.google.android.gms.tasks.OnCompleteListener;
import com.google.android.gms.tasks.Task;
import com.google.android.gms.tasks.f;
import com.onetrust.otpublishers.headless.UI.fragment.q;
import com.quizlet.data.connectivity.NetworkOfflineError;
import com.quizlet.data.model.AbstractC4119d0;
import com.quizlet.data.model.BasicCourseFolder;
import com.quizlet.data.model.ContentFolder;
import com.quizlet.data.model.CreatedFolder;
import com.quizlet.data.model.FullCourseFolder;
import com.quizlet.db.data.caches.UserInfoCache;
import com.quizlet.db.data.models.persisted.DBUser;
import com.quizlet.infra.legacysyncengine.models.identity.QueryIdFieldChangeMapper;
import com.quizlet.quizletandroid.ui.common.ads.C4636c;
import com.quizlet.quizletandroid.ui.profile.UserSetListFragment;
import com.quizlet.remote.model.folderstudymaterial.j;
import io.reactivex.rxjava3.core.i;
import io.reactivex.rxjava3.core.p;
import io.reactivex.rxjava3.functions.h;
import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import kotlin.NoWhenBranchMatchedException;
import kotlin.collections.A;
import kotlin.collections.C;
import kotlin.jvm.internal.Intrinsics;
import kotlin.l;
import kotlin.m;
import kotlinx.coroutines.AbstractC5040y;

/* loaded from: classes2.dex */
public class c implements androidx.camera.core.impl.utils.futures.c, k, OnCompleteListener, InterfaceC1062t, com.google.firebase.crashlytics.internal.stacktrace.a, h, dagger.android.b, com.quizlet.mapper.a {
    public static c d;
    public final /* synthetic */ int a;
    public final Object b;
    public Object c;

    public /* synthetic */ c(int i, Object obj, Object obj2) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
    }

    public static void j(c cVar, d dVar, float f, int i) {
        if ((i & 2) != 0) {
            f = 0;
        }
        float f2 = 0;
        cVar.getClass();
        int i2 = dVar.b;
        String str = "start";
        if (i2 != -2) {
            if (i2 == -1) {
                str = "end";
            } else if (i2 != 1) {
                Log.e("CCL", "verticalAnchorIndexToAnchorName: Unknown vertical index");
            } else {
                str = "right";
            }
        }
        androidx.constraintlayout.core.parser.a aVar = new androidx.constraintlayout.core.parser.a(new char[0]);
        aVar.i(androidx.constraintlayout.core.parser.h.i(dVar.a.toString()));
        aVar.i(androidx.constraintlayout.core.parser.h.i(str));
        aVar.i(new e(f));
        aVar.i(new e(f2));
        ((g) cVar.b).B((String) cVar.c, aVar);
    }

    /* JADX WARN: Removed duplicated region for block: B:19:0x0087  */
    @Override // com.quizlet.mapper.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object a(java.lang.Object r10) {
        /*
            Method dump skipped, instructions count: 389
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.repository.searchexplanations.c.a(java.lang.Object):java.lang.Object");
    }

    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        switch (this.a) {
            case 13:
                com.quizlet.data.connectivity.b status = (com.quizlet.data.connectivity.b) obj;
                Intrinsics.checkNotNullParameter(status, "status");
                return status.a ? (i) ((u) this.b).invoke() : (i) ((u) this.c).invoke();
            case 17:
                Throwable e = (Throwable) obj;
                Intrinsics.checkNotNullParameter(e, "e");
                if (!(e instanceof NetworkOfflineError)) {
                    return p.f(A.b((AbstractC4119d0) this.c));
                }
                ((com.quizlet.data.repository.folder.i) this.b).d.j("no network connection", e);
                return p.d(new NetworkOfflineError(0));
            case 21:
                Map serverIdToLocalIdMap = (Map) obj;
                Intrinsics.checkNotNullParameter(serverIdToLocalIdMap, "serverIdToLocalIdMap");
                ((com.quizlet.local.ormlite.models.bookmark.a) this.b).getClass();
                List<AbstractC4119d0> list = (List) this.c;
                ArrayList arrayList = new ArrayList(C.q(list, 10));
                for (AbstractC4119d0 abstractC4119d0N : list) {
                    Long l = (Long) serverIdToLocalIdMap.get(Long.valueOf(abstractC4119d0N.a()));
                    if ((abstractC4119d0N instanceof CreatedFolder) && l != null) {
                        CreatedFolder createdFolder = (CreatedFolder) abstractC4119d0N;
                        long jLongValue = l.longValue();
                        if (createdFolder instanceof ContentFolder) {
                            abstractC4119d0N = ContentFolder.l((ContentFolder) createdFolder, jLongValue, null, null, 32759);
                        } else if (createdFolder instanceof BasicCourseFolder) {
                            abstractC4119d0N = BasicCourseFolder.n((BasicCourseFolder) createdFolder, jLongValue, null, 16375);
                        } else {
                            if (!(createdFolder instanceof FullCourseFolder)) {
                                throw new NoWhenBranchMatchedException();
                            }
                            abstractC4119d0N = FullCourseFolder.n((FullCourseFolder) createdFolder, jLongValue, null, 32759);
                        }
                    }
                    arrayList.add(abstractC4119d0N);
                }
                return arrayList;
            case EventType.WINDOW_STATE /* 22 */:
                Intrinsics.checkNotNullParameter((Boolean) obj, "it");
                List list2 = (List) this.b;
                Intrinsics.d(list2);
                Object obj2 = ((com.quizlet.local.ormlite.models.bookmark.a) this.c).c;
                ArrayList arrayList2 = new ArrayList(C.q(list2, 10));
                Iterator it2 = list2.iterator();
                while (it2.hasNext()) {
                    arrayList2.add(assistantMode.utils.studiableMetadata.b.O((DBUser) it2.next()));
                }
                return arrayList2;
            case EventType.VIDEO /* 24 */:
                s sVar = (s) this.b;
                V v = (V) sVar.f;
                return new com.quizlet.data.repository.classfolder.e(((QueryIdFieldChangeMapper) sVar.d).convertStaleLocalIds((com.quizlet.infra.legacysyncengine.orm.query.a) this.c), (com.quizlet.infra.legacysyncengine.net.listeners.d) v.b, v, 13).k().x(16).e(new q((com.quizlet.quizletandroid.data.management.b) obj, 26));
            default:
                Boolean it3 = (Boolean) obj;
                Intrinsics.checkNotNullParameter(it3, "it");
                return it3.booleanValue() ? (io.reactivex.rxjava3.internal.operators.single.g) this.b : (io.reactivex.rxjava3.internal.operators.flowable.b) this.c;
        }
    }

    public void b(E e) {
        if (e.E()) {
            ((r0) this.c).add(e);
        } else {
            W4.f("DepthSortedSet.add called on an unattached node");
            throw null;
        }
    }

    public int c(ArrayList arrayList, androidx.camera.core.impl.utils.executor.k kVar, CameraCaptureSession.CaptureCallback captureCallback) {
        return ((CameraCaptureSession) this.b).captureBurst(arrayList, new C0135l(kVar, captureCallback), ((androidx.camera.camera2.internal.compat.h) this.c).a);
    }

    @Override // dagger.android.b
    public void d(Object obj) {
        UserSetListFragment userSetListFragment = (UserSetListFragment) obj;
        com.quizlet.quizletandroid.u uVar = (com.quizlet.quizletandroid.u) this.b;
        userSetListFragment.a = uVar.w();
        userSetListFragment.b = uVar.S0();
        userSetListFragment.u = new n(com.quizlet.featuregate.injection.a.d(), new com.quizlet.data.repository.user.a(uVar.m1(), uVar.o(), (com.quizlet.cache.a) ((dagger.internal.c) this.c).get()), uVar.l0(), (com.quizlet.infra.legacysyncengine.net.c) uVar.Q.get());
        userSetListFragment.v = (com.quizlet.infra.legacysyncengine.net.c) uVar.Q.get();
        uVar.Z();
        userSetListFragment.w = (com.quizlet.features.setpage.utils.setpermissions.a) uVar.h1.get();
        SharedPreferences sharedPreferences = uVar.A0();
        Intrinsics.checkNotNullParameter(sharedPreferences, "sharedPreferences");
        userSetListFragment.x = new com.quizlet.features.setpage.upsell.a(sharedPreferences, 1);
        userSetListFragment.y = (com.quizlet.offline.managers.b) uVar.d1.get();
    }

    @Override // com.google.firebase.crashlytics.internal.stacktrace.a
    public StackTraceElement[] e(StackTraceElement[] stackTraceElementArr) {
        if (stackTraceElementArr.length <= 1024) {
            return stackTraceElementArr;
        }
        com.google.firebase.crashlytics.internal.stacktrace.a[] aVarArr = (com.google.firebase.crashlytics.internal.stacktrace.a[]) this.b;
        StackTraceElement[] stackTraceElementArrE = stackTraceElementArr;
        for (int i = 0; i < 1; i++) {
            com.google.firebase.crashlytics.internal.stacktrace.a aVar = aVarArr[i];
            if (stackTraceElementArrE.length <= 1024) {
                break;
            }
            stackTraceElementArrE = aVar.e(stackTraceElementArr);
        }
        return stackTraceElementArrE.length > 1024 ? ((com.quizlet.shared.usecase.srs.a) this.c).e(stackTraceElementArrE) : stackTraceElementArrE;
    }

    /* JADX WARN: Removed duplicated region for block: B:16:0x003e  */
    /* JADX WARN: Removed duplicated region for block: B:17:0x0046  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public com.google.android.datatransport.cct.CctBackendFactory f(java.lang.String r14) throws android.content.pm.PackageManager.NameNotFoundException {
        /*
            Method dump skipped, instructions count: 273
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.repository.searchexplanations.c.f(java.lang.String):com.google.android.datatransport.cct.CctBackendFactory");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object g(java.lang.String r5, com.quizlet.generated.enums.y1 r6, java.lang.Long r7, kotlin.coroutines.jvm.internal.c r8) {
        /*
            r4 = this;
            boolean r0 = r8 instanceof com.quizlet.remote.model.foldertoadd.a
            if (r0 == 0) goto L13
            r0 = r8
            com.quizlet.remote.model.foldertoadd.a r0 = (com.quizlet.remote.model.foldertoadd.a) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.quizlet.remote.model.foldertoadd.a r0 = new com.quizlet.remote.model.foldertoadd.a
            r0.<init>(r4, r8)
        L18:
            java.lang.Object r8 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            if (r2 == 0) goto L35
            if (r2 != r3) goto L2d
            com.quizlet.data.repository.searchexplanations.c r5 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r8)
            kotlin.r r8 = (kotlin.r) r8
            java.lang.Object r6 = r8.a
            goto L48
        L2d:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L35:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            r0.j = r4
            r0.m = r3
            java.lang.Object r8 = r4.b
            com.quizlet.remote.model.folderstudymaterial.j r8 = (com.quizlet.remote.model.folderstudymaterial.j) r8
            java.lang.Object r6 = r8.c(r5, r6, r7, r0)
            if (r6 != r1) goto L47
            return r1
        L47:
            r5 = r4
        L48:
            java.lang.Object r5 = r5.c
            kotlin.p r5 = kotlin.r.b
            boolean r5 = r6 instanceof kotlin.q
            if (r5 != 0) goto L57
            com.quizlet.remote.model.foldertoadd.FolderToAddMaterialResponse r6 = (com.quizlet.remote.model.foldertoadd.FolderToAddMaterialResponse) r6
            java.util.List r5 = com.quizlet.remote.model.foldertoadd.b.a(r6)
            return r5
        L57:
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.repository.searchexplanations.c.g(java.lang.String, com.quizlet.generated.enums.y1, java.lang.Long, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public okhttp3.s h(String url, String campaign) {
        okhttp3.s sVarD;
        Intrinsics.checkNotNullParameter(url, "url");
        Intrinsics.checkNotNullParameter(campaign, "campaign");
        Intrinsics.checkNotNullParameter(url, "<this>");
        try {
            Intrinsics.checkNotNullParameter(url, "<this>");
            C1372j c1372j = new C1372j();
            c1372j.l(null, url);
            sVarD = c1372j.d();
        } catch (IllegalArgumentException unused) {
            sVarD = null;
        }
        if (sVarD == null) {
            return null;
        }
        C1372j c1372jF = sVarD.f();
        com.quizlet.utmhelper.b bVarA = ((com.quizlet.utmhelper.d) ((com.quizlet.utmhelper.c) this.c)).a(new com.quizlet.utmhelper.a(Long.valueOf(((UserInfoCache) this.b).getPersonId()), campaign, "share-link", "share-sheet-android"));
        c1372jF.c("x", bVarA.b);
        c1372jF.c("i", bVarA.a);
        return c1372jF.d();
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object i(java.lang.String r5, kotlin.coroutines.jvm.internal.c r6) throws java.lang.Throwable {
        /*
            r4 = this;
            boolean r0 = r6 instanceof com.quizlet.data.interactor.search.b
            if (r0 == 0) goto L13
            r0 = r6
            com.quizlet.data.interactor.search.b r0 = (com.quizlet.data.interactor.search.b) r0
            int r1 = r0.n
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.n = r1
            goto L18
        L13:
            com.quizlet.data.interactor.search.b r0 = new com.quizlet.data.interactor.search.b
            r0.<init>(r4, r6)
        L18:
            java.lang.Object r6 = r0.l
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.n
            r3 = 1
            if (r2 == 0) goto L35
            if (r2 != r3) goto L2d
            java.lang.String r5 = r0.k
            com.quizlet.data.repository.searchexplanations.c r0 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r6)     // Catch: java.lang.Exception -> L2b
            goto L61
        L2b:
            r6 = move-exception
            goto L84
        L2d:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L35:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            java.lang.Object r6 = r4.c
            com.quizlet.cache.a r6 = (com.quizlet.cache.a) r6
            java.lang.Object r6 = r6.get(r5)
            com.quizlet.data.model.C1 r6 = (com.quizlet.data.model.C1) r6
            if (r6 == 0) goto L45
            return r6
        L45:
            java.lang.Object r6 = r4.b     // Catch: java.lang.Exception -> L2b
            com.google.android.gms.internal.appset.e r6 = (com.google.android.gms.internal.appset.e) r6     // Catch: java.lang.Exception -> L2b
            r0.j = r4     // Catch: java.lang.Exception -> L2b
            r0.k = r5     // Catch: java.lang.Exception -> L2b
            r0.n = r3     // Catch: java.lang.Exception -> L2b
            com.quizlet.remote.model.search.e r2 = new com.quizlet.remote.model.search.e     // Catch: java.lang.Exception -> L2b
            r3 = 0
            r2.<init>(r6, r5, r3)     // Catch: java.lang.Exception -> L2b
            java.lang.Object r6 = r6.d     // Catch: java.lang.Exception -> L2b
            kotlinx.coroutines.y r6 = (kotlinx.coroutines.AbstractC5040y) r6     // Catch: java.lang.Exception -> L2b
            java.lang.Object r6 = kotlinx.coroutines.E.J(r6, r2, r0)     // Catch: java.lang.Exception -> L2b
            if (r6 != r1) goto L60
            return r1
        L60:
            r0 = r4
        L61:
            com.quizlet.data.model.C1 r6 = (com.quizlet.data.model.C1) r6     // Catch: java.lang.Exception -> L2b
            java.lang.String r1 = r6.a     // Catch: java.lang.Exception -> L2b
            java.util.List r6 = r6.b     // Catch: java.lang.Exception -> L2b
            com.google.zxing.aztec.encoder.c r2 = new com.google.zxing.aztec.encoder.c     // Catch: java.lang.Exception -> L2b
            r3 = 8
            r2.<init>(r3)     // Catch: java.lang.Exception -> L2b
            java.util.List r6 = kotlin.collections.CollectionsKt.n0(r6, r2)     // Catch: java.lang.Exception -> L2b
            r2 = 6
            java.util.List r6 = kotlin.collections.CollectionsKt.p0(r6, r2)     // Catch: java.lang.Exception -> L2b
            com.quizlet.data.model.C1 r2 = new com.quizlet.data.model.C1     // Catch: java.lang.Exception -> L2b
            r2.<init>(r1, r6)     // Catch: java.lang.Exception -> L2b
            java.lang.Object r6 = r0.c     // Catch: java.lang.Exception -> L2b
            com.quizlet.cache.a r6 = (com.quizlet.cache.a) r6     // Catch: java.lang.Exception -> L2b
            r6.a(r5, r2)     // Catch: java.lang.Exception -> L2b
            return r2
        L84:
            com.quizlet.data.repository.search.exception.SearchTypeAheadException r0 = new com.quizlet.data.repository.search.exception.SearchTypeAheadException
            java.lang.String r1 = "query"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r5, r1)
            java.lang.String r1 = "e"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r6, r1)
            java.lang.String r1 = "Could not get type ahead suggestions for "
            java.lang.String r5 = androidx.camera.camera2.internal.AbstractC0147y.d(r1, r5)
            r0.<init>(r5, r6)
            throw r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.repository.searchexplanations.c.i(java.lang.String, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public boolean k(E e) {
        if (e.E()) {
            return ((r0) this.c).remove(e);
        }
        W4.f("DepthSortedSet.remove called on an unattached node");
        throw null;
    }

    /* JADX WARN: Removed duplicated region for block: B:8:0x0016  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object l(java.lang.String r13, java.lang.Integer r14, java.lang.String r15, java.lang.Integer r16, java.util.List r17, boolean r18, kotlin.coroutines.jvm.internal.c r19) throws java.lang.Throwable {
        /*
            r12 = this;
            r0 = r19
            boolean r2 = r0 instanceof com.quizlet.data.repository.searchexplanations.a
            if (r2 == 0) goto L16
            r2 = r0
            com.quizlet.data.repository.searchexplanations.a r2 = (com.quizlet.data.repository.searchexplanations.a) r2
            int r3 = r2.l
            r4 = -2147483648(0xffffffff80000000, float:-0.0)
            r5 = r3 & r4
            if (r5 == 0) goto L16
            int r3 = r3 - r4
            r2.l = r3
        L14:
            r9 = r2
            goto L1c
        L16:
            com.quizlet.data.repository.searchexplanations.a r2 = new com.quizlet.data.repository.searchexplanations.a
            r2.<init>(r12, r0)
            goto L14
        L1c:
            java.lang.Object r0 = r9.j
            kotlin.coroutines.intrinsics.a r10 = kotlin.coroutines.intrinsics.a.a
            int r2 = r9.l
            r11 = 1
            if (r2 == 0) goto L33
            if (r2 != r11) goto L2b
            androidx.glance.appwidget.protobuf.Z.e(r0)
            goto L53
        L2b:
            java.lang.IllegalStateException r0 = new java.lang.IllegalStateException
            java.lang.String r2 = "call to 'resume' before 'invoke' with coroutine"
            r0.<init>(r2)
            throw r0
        L33:
            androidx.glance.appwidget.protobuf.Z.e(r0)
            com.quizlet.data.repository.searchexplanations.b r0 = new com.quizlet.data.repository.searchexplanations.b
            r8 = 0
            r1 = r12
            r2 = r13
            r3 = r14
            r4 = r15
            r5 = r16
            r6 = r17
            r7 = r18
            r0.<init>(r1, r2, r3, r4, r5, r6, r7, r8)
            r9.l = r11
            java.lang.Object r2 = r12.c
            kotlinx.coroutines.y r2 = (kotlinx.coroutines.AbstractC5040y) r2
            java.lang.Object r0 = kotlinx.coroutines.E.J(r2, r0, r9)
            if (r0 != r10) goto L53
            return r10
        L53:
            java.lang.String r2 = "withContext(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r0, r2)
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.repository.searchexplanations.c.l(java.lang.String, java.lang.Integer, java.lang.String, java.lang.Integer, java.util.List, boolean, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    @Override // com.bumptech.glide.load.b
    public boolean m(Object obj, File file, com.bumptech.glide.load.h hVar) {
        return ((C1539b) this.c).m(new C1541d(((BitmapDrawable) ((v) obj).get()).getBitmap(), (com.bumptech.glide.load.engine.bitmap_recycle.a) this.b), file, hVar);
    }

    @Override // com.bumptech.glide.load.k
    public int n(com.bumptech.glide.load.h hVar) {
        return 2;
    }

    public int o(CaptureRequest captureRequest, androidx.camera.core.impl.utils.executor.k kVar, CameraCaptureSession.CaptureCallback captureCallback) {
        return ((CameraCaptureSession) this.b).setRepeatingRequest(captureRequest, new C0135l(kVar, captureCallback), ((androidx.camera.camera2.internal.compat.h) this.c).a);
    }

    @Override // com.google.android.gms.tasks.OnCompleteListener
    public void onComplete(Task task) {
        ((Map) ((com.quizlet.data.repository.explanations.myexplanations.a) this.c).c).remove((f) this.b);
    }

    @Override // androidx.camera.core.impl.utils.futures.c
    public void onFailure(Throwable t) {
        Intrinsics.checkNotNullParameter(t, "t");
        ((androidx.concurrent.futures.i) this.b).d(t);
    }

    @Override // androidx.camera.core.impl.utils.futures.c, io.reactivex.rxjava3.core.q, com.google.android.gms.tasks.d
    public void onSuccess(Object obj) {
        ((androidx.concurrent.futures.i) this.b).b((C0194q) this.c);
    }

    public synchronized void p(long j, long j2, int i) {
        AtomicLong atomicLong = (AtomicLong) this.c;
        long jElapsedRealtime = SystemClock.elapsedRealtime();
        if (atomicLong.get() != -1 && jElapsedRealtime - ((AtomicLong) this.c).get() <= TimeUnit.MINUTES.toMillis(30L)) {
            return;
        }
        ((com.google.android.gms.common.internal.service.b) this.b).d(new TelemetryData(0, Arrays.asList(new MethodInvocation(24335, i, 0, j, j2, null, null, 0, -1)))).o(new l1(this, jElapsedRealtime, 12));
    }

    public String toString() {
        switch (this.a) {
            case 3:
                return ((r0) this.c).toString();
            default:
                return super.toString();
        }
    }

    @Override // androidx.core.view.InterfaceC1062t
    public D0 w(D0 d0, View view) {
        com.google.android.gms.ads.internal.overlay.k kVar = new com.google.android.gms.ads.internal.overlay.k();
        com.google.android.gms.ads.internal.overlay.k kVar2 = (com.google.android.gms.ads.internal.overlay.k) this.c;
        kVar.a = kVar2.a;
        kVar.b = kVar2.b;
        kVar.c = kVar2.c;
        kVar.d = kVar2.d;
        return ((com.google.android.material.internal.s) this.b).k(view, d0, kVar);
    }

    public c(com.onetrust.otpublishers.headless.Internal.Helper.h hVar, com.google.mlkit.common.sdkinternal.model.a aVar) {
        this.a = 12;
        this.b = aVar;
    }

    public c(com.quizlet.data.repository.explanations.myexplanations.a aVar, f fVar) {
        this.a = 8;
        this.b = fVar;
        this.c = aVar;
    }

    public c(com.quizlet.quizletandroid.ui.group.data.b dataSourceFactory) {
        this.a = 26;
        Intrinsics.checkNotNullParameter(dataSourceFactory, "dataSourceFactory");
        this.b = dataSourceFactory;
    }

    public c(Context context, SharedPreferences sharedPreferences) {
        this.a = 20;
        com.quizlet.inapp.util.a semanticAppVersionProvider = com.quizlet.inapp.util.a.a;
        Intrinsics.checkNotNullParameter(sharedPreferences, "sharedPreferences");
        Intrinsics.checkNotNullParameter(semanticAppVersionProvider, "semanticAppVersionProvider");
        Intrinsics.checkNotNullParameter(context, "context");
        this.b = sharedPreferences;
        this.c = context;
    }

    public c(j dataSource, com.quizlet.remote.model.foldertoadd.b mapper) {
        this.a = 28;
        Intrinsics.checkNotNullParameter(dataSource, "dataSource");
        Intrinsics.checkNotNullParameter(mapper, "mapper");
        this.b = dataSource;
        this.c = mapper;
    }

    public c(com.quizlet.data.repository.folderset.c repository, androidx.work.impl.model.c dispatcher) {
        this.a = 15;
        Intrinsics.checkNotNullParameter(repository, "repository");
        Intrinsics.checkNotNullParameter(dispatcher, "dispatcher");
        this.b = repository;
        this.c = dispatcher;
    }

    public c(com.google.android.gms.internal.appset.e repository, com.quizlet.cache.a cache) {
        this.a = 16;
        Intrinsics.checkNotNullParameter(repository, "repository");
        Intrinsics.checkNotNullParameter(cache, "cache");
        this.b = repository;
        this.c = cache;
    }

    public c(com.quizlet.shared.usecase.eligibility.c checkEligibilityUseCase, AbstractC5040y ioDispatcher) {
        this.a = 29;
        Intrinsics.checkNotNullParameter(checkEligibilityUseCase, "checkEligibilityUseCase");
        Intrinsics.checkNotNullParameter(ioDispatcher, "ioDispatcher");
        this.b = checkEligibilityUseCase;
        this.c = ioDispatcher;
    }

    public c(com.quizlet.remote.model.explanations.question.recommendations.b repository, AbstractC5040y ioDispatcher) {
        this.a = 14;
        Intrinsics.checkNotNullParameter(repository, "repository");
        Intrinsics.checkNotNullParameter(ioDispatcher, "ioDispatcher");
        this.b = repository;
        this.c = ioDispatcher;
    }

    public c(Context context, C4636c adSizeCreator) {
        this.a = 25;
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(adSizeCreator, "adSizeCreator");
        this.b = context;
        this.c = adSizeCreator;
    }

    public c(com.quizlet.data.interactor.studiablemetadata.b getSupportedStudiableMetadataByTypeUseCase, AbstractC5040y ioDispatcher) {
        this.a = 19;
        Intrinsics.checkNotNullParameter(getSupportedStudiableMetadataByTypeUseCase, "getSupportedStudiableMetadataByTypeUseCase");
        Intrinsics.checkNotNullParameter(ioDispatcher, "ioDispatcher");
        this.b = getSupportedStudiableMetadataByTypeUseCase;
        this.c = ioDispatcher;
    }

    public c(UserInfoCache userInfoCache, com.quizlet.utmhelper.c utmParamsHelper) {
        this.a = 18;
        Intrinsics.checkNotNullParameter(userInfoCache, "userInfoCache");
        Intrinsics.checkNotNullParameter(utmParamsHelper, "utmParamsHelper");
        this.b = userInfoCache;
        this.c = utmParamsHelper;
    }

    public c(com.google.firebase.crashlytics.internal.stacktrace.a[] aVarArr) {
        this.a = 11;
        this.b = aVarArr;
        this.c = new com.quizlet.shared.usecase.srs.a(18);
    }

    public c() {
        this.a = 3;
        this.b = l.a(m.c, C0913i.c);
        this.c = new r0(new e0(1));
    }

    public c(WorkDatabase_Impl database) {
        this.a = 5;
        Intrinsics.checkNotNullParameter(database, "database");
        this.b = database;
        Set setNewSetFromMap = Collections.newSetFromMap(new IdentityHashMap());
        Intrinsics.checkNotNullExpressionValue(setNewSetFromMap, "newSetFromMap(IdentityHashMap())");
        this.c = setNewSetFromMap;
    }

    public c(CameraCaptureSession cameraCaptureSession, androidx.camera.camera2.internal.compat.h hVar) {
        this.a = 1;
        cameraCaptureSession.getClass();
        this.b = cameraCaptureSession;
        this.c = hVar;
    }

    public c(androidx.work.impl.model.v remoteDataStore, com.quizlet.data.connectivity.a networkStatus, org.slf4j.b logger, AbstractC5040y dispatcher) {
        this.a = 0;
        Intrinsics.checkNotNullParameter(remoteDataStore, "remoteDataStore");
        Intrinsics.checkNotNullParameter(networkStatus, "networkStatus");
        Intrinsics.checkNotNullParameter(logger, "logger");
        Intrinsics.checkNotNullParameter(dispatcher, "dispatcher");
        this.b = remoteDataStore;
        this.c = dispatcher;
    }

    public c(int i, g gVar) {
        this.a = 4;
        this.b = gVar;
        String str = "start";
        if (i != -2) {
            if (i == -1) {
                str = "end";
            } else if (i == 0) {
                str = "left";
            } else if (i != 1) {
                Log.e("CCL", "verticalAnchorIndexToAnchorName: Unknown vertical index");
            } else {
                str = "right";
            }
        }
        this.c = str;
    }

    public c(Context context, int i) {
        this.a = i;
        switch (i) {
            case 9:
                this.c = new AtomicLong(-1L);
                this.b = com.google.android.gms.common.internal.u.n(context, new com.google.android.gms.common.internal.k("mlkit:vision"));
                break;
            default:
                this.c = null;
                this.b = context;
                break;
        }
    }

    public c(com.quizlet.quizletandroid.u uVar) {
        this.a = 23;
        this.b = uVar;
        this.c = dagger.internal.d.a(new com.google.firebase.perf.injection.modules.a());
    }
}
