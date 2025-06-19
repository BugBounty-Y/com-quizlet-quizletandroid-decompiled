package com.perimeterx.mobile_sdk.session;

import android.app.Application;
import android.hardware.SensorManager;
import android.os.Handler;
import android.os.Looper;
import androidx.camera.camera2.internal.RunnableC0131h;
import androidx.compose.foundation.gestures.l1;
import androidx.lifecycle.InterfaceC1250k;
import androidx.lifecycle.d0;
import com.google.android.gms.internal.mlkit_vision_camera.D1;
import com.google.android.gms.internal.mlkit_vision_document_scanner.A4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3744v4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.F4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.L4;
import com.perimeterx.mobile_sdk.PerimeterXDelegate;
import com.perimeterx.mobile_sdk.PerimeterXErrorCode;
import com.perimeterx.mobile_sdk.main.PXPolicy;
import com.perimeterx.mobile_sdk.main.PXStorageMethod;
import java.io.IOException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.Random;
import java.util.Timer;
import java.util.UUID;
import kotlin.NoWhenBranchMatchedException;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.J;
import kotlinx.coroutines.E;
import kotlinx.coroutines.O;

/* loaded from: classes2.dex */
public final class l implements InterfaceC1250k {
    public static Application b;
    public static Timer f;
    public static volatile long h;
    public static final String i;
    public static final Date j;
    public static boolean k;
    public static final l a = new l();
    public static final ArrayList c = new ArrayList();
    public static final com.google.firebase.messaging.u d = new com.google.firebase.messaging.u(6);
    public static final kotlinx.coroutines.sync.c e = kotlinx.coroutines.sync.d.a();
    public static final kotlinx.coroutines.sync.c g = kotlinx.coroutines.sync.d.a();

    static {
        com.fasterxml.uuid.c cVar;
        long j2;
        synchronized (com.fasterxml.uuid.b.class) {
            if (com.fasterxml.uuid.b.a == null) {
                try {
                    com.fasterxml.uuid.b.a = new com.fasterxml.uuid.c(new Random(System.currentTimeMillis()));
                } catch (IOException e2) {
                    throw new IllegalArgumentException("Failed to create UUIDTimer with specified synchronizer: " + e2.getMessage(), e2);
                }
            }
            cVar = com.fasterxml.uuid.b.a;
        }
        l1 l1Var = new l1(cVar);
        com.fasterxml.uuid.c cVar2 = (com.fasterxml.uuid.c) l1Var.c;
        synchronized (cVar2) {
            try {
                long jCurrentTimeMillis = System.currentTimeMillis();
                if (jCurrentTimeMillis < cVar2.d) {
                    cVar2.a.b(String.format("System time going backwards! (got value %d, last %d)", Long.valueOf(jCurrentTimeMillis), Long.valueOf(cVar2.d)));
                    cVar2.d = jCurrentTimeMillis;
                }
                long j3 = cVar2.e;
                if (jCurrentTimeMillis <= j3) {
                    if (cVar2.f >= 10000) {
                        long j4 = j3 - jCurrentTimeMillis;
                        j3++;
                        cVar2.a.b("Timestamp over-run: need to reinitialize random sequence");
                        int iNextInt = cVar2.b.nextInt();
                        cVar2.c = iNextInt;
                        cVar2.f = (iNextInt >> 16) & 255;
                        if (j4 >= 100) {
                            long j5 = j4 / 100;
                            long j6 = 2;
                            if (j5 < 2) {
                                j6 = 1;
                            } else if (j5 >= 10) {
                                j6 = j5 < 600 ? 3L : 5L;
                            }
                            cVar2.a.b(String.format("Need to wait for %d milliseconds; virtual clock advanced too far in the future", Long.valueOf(j6)));
                            long j7 = jCurrentTimeMillis + j6;
                            int i2 = 0;
                            while (true) {
                                try {
                                    Thread.sleep(j6);
                                } catch (InterruptedException unused) {
                                }
                                i2++;
                                if (i2 > 50 || System.currentTimeMillis() >= j7) {
                                    break;
                                } else {
                                    j6 = 1;
                                }
                            }
                        }
                    }
                    jCurrentTimeMillis = j3;
                } else {
                    cVar2.f &= 255;
                }
                cVar2.e = jCurrentTimeMillis;
                int i3 = cVar2.f;
                j2 = (jCurrentTimeMillis * 10000) + 122192928000000000L + i3;
                cVar2.f = i3 + 1;
            } catch (Throwable th) {
                throw th;
            }
        }
        int i4 = (int) (j2 >>> 32);
        String string = new UUID((((int) j2) << 32) | ((((((i4 << 16) | (i4 >>> 16)) & (-61441)) | 4096) << 32) >>> 32), l1Var.b).toString();
        Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
        i = string;
        j = new Date();
    }

    public static d a(String str) throws Throwable {
        J j2 = new J();
        E.D(kotlin.coroutines.n.a, new j(j2, str, null, 0));
        return (d) j2.a;
    }

    public static d b(URL url, com.perimeterx.mobile_sdk.business_logic.b source) {
        Intrinsics.checkNotNullParameter(url, "url");
        Intrinsics.checkNotNullParameter(source, "source");
        J j2 = new J();
        E.D(kotlin.coroutines.n.a, new k(j2, url, source, null));
        return (d) j2.a;
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object c(com.perimeterx.mobile_sdk.api_data.j r8, kotlin.coroutines.jvm.internal.c r9) throws java.lang.Throwable {
        /*
            boolean r0 = r9 instanceof com.perimeterx.mobile_sdk.session.h
            if (r0 == 0) goto L13
            r0 = r9
            com.perimeterx.mobile_sdk.session.h r0 = (com.perimeterx.mobile_sdk.session.h) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.perimeterx.mobile_sdk.session.h r0 = new com.perimeterx.mobile_sdk.session.h
            r0.<init>(r9)
        L18:
            java.lang.Object r9 = r0.l
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 0
            r4 = 1
            if (r2 == 0) goto L34
            if (r2 != r4) goto L2c
            java.util.Iterator r8 = r0.k
            com.perimeterx.mobile_sdk.api_data.j r2 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r9)
            goto L54
        L2c:
            java.lang.IllegalStateException r8 = new java.lang.IllegalStateException
            java.lang.String r9 = "call to 'resume' before 'invoke' with coroutine"
            r8.<init>(r9)
            throw r8
        L34:
            androidx.glance.appwidget.protobuf.Z.e(r9)
            kotlin.jvm.internal.J r9 = new kotlin.jvm.internal.J
            r9.<init>()
            com.perimeterx.mobile_sdk.session.f r2 = new com.perimeterx.mobile_sdk.session.f
            r5 = 0
            r2.<init>(r9, r3, r5)
            kotlinx.coroutines.E.E(r2)
            java.lang.Object r9 = r9.a
            java.util.ArrayList r9 = (java.util.ArrayList) r9
            java.util.Iterator r9 = r9.iterator()
            java.lang.String r2 = "iterator(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r9, r2)
            r2 = r8
            r8 = r9
        L54:
            boolean r9 = r8.hasNext()
            if (r9 == 0) goto L83
            java.lang.Object r9 = r8.next()
            java.lang.String r5 = "next(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r9, r5)
            com.perimeterx.mobile_sdk.session.d r9 = (com.perimeterx.mobile_sdk.session.d) r9
            r0.j = r2
            r0.k = r8
            r0.m = r4
            r9.getClass()
            kotlinx.coroutines.scheduling.e r5 = kotlinx.coroutines.O.a
            kotlinx.coroutines.internal.d r5 = kotlinx.coroutines.E.c(r5)
            com.perimeterx.mobile_sdk.doctor_app.a r6 = new com.perimeterx.mobile_sdk.doctor_app.a
            r7 = 1
            r6.<init>(r9, r2, r3, r7)
            r9 = 3
            kotlinx.coroutines.E.A(r5, r3, r3, r6, r9)
            kotlin.Unit r9 = kotlin.Unit.a
            if (r9 != r1) goto L54
            return r1
        L83:
            kotlin.Unit r8 = kotlin.Unit.a
            return r8
        */
        throw new UnsupportedOperationException("Method not decompiled: com.perimeterx.mobile_sdk.session.l.c(com.perimeterx.mobile_sdk.api_data.j, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object f(com.perimeterx.mobile_sdk.api_data.j r5, kotlin.coroutines.jvm.internal.c r6) {
        /*
            boolean r0 = r6 instanceof com.perimeterx.mobile_sdk.session.i
            if (r0 == 0) goto L13
            r0 = r6
            com.perimeterx.mobile_sdk.session.i r0 = (com.perimeterx.mobile_sdk.session.i) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.perimeterx.mobile_sdk.session.i r0 = new com.perimeterx.mobile_sdk.session.i
            r0.<init>(r6)
        L18:
            java.lang.Object r6 = r0.l
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            if (r2 == 0) goto L33
            if (r2 != r3) goto L2b
            java.util.Iterator r5 = r0.k
            com.perimeterx.mobile_sdk.api_data.j r2 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L43
        L2b:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L33:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            java.util.ArrayList r6 = com.perimeterx.mobile_sdk.session.l.c
            java.util.Iterator r6 = r6.iterator()
            java.lang.String r2 = "iterator(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r6, r2)
            r2 = r5
            r5 = r6
        L43:
            boolean r6 = r5.hasNext()
            if (r6 == 0) goto L61
            java.lang.Object r6 = r5.next()
            java.lang.String r4 = "next(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r6, r4)
            com.perimeterx.mobile_sdk.session.d r6 = (com.perimeterx.mobile_sdk.session.d) r6
            r0.j = r2
            r0.k = r5
            r0.m = r3
            java.lang.Object r6 = r6.j(r2, r0)
            if (r6 != r1) goto L43
            return r1
        L61:
            kotlin.Unit r5 = kotlin.Unit.a
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.perimeterx.mobile_sdk.session.l.f(com.perimeterx.mobile_sdk.api_data.j, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public final void e(Application context, ArrayList appIds, PerimeterXDelegate perimeterXDelegate, PXPolicy policy) throws Exception {
        com.perimeterx.mobile_sdk.local_data.c storageType;
        com.perimeterx.mobile_sdk.local_data.b aVar;
        Application application;
        int i2 = 1;
        Intrinsics.checkNotNullParameter(context, "application");
        Intrinsics.checkNotNullParameter(appIds, "appIds");
        Intrinsics.checkNotNullParameter(policy, "policy");
        ArrayList appIds2 = new ArrayList();
        Iterator it2 = appIds.iterator();
        Intrinsics.checkNotNullExpressionValue(it2, "iterator(...)");
        while (it2.hasNext()) {
            Object next = it2.next();
            Intrinsics.checkNotNullExpressionValue(next, "next(...)");
            String str = (String) next;
            if (str.length() > 0) {
                appIds2.add(str);
            }
        }
        if (appIds2.isEmpty()) {
            throw new Exception(PerimeterXErrorCode.MISSING_APP_ID.message$PerimeterX_release());
        }
        if (!c.isEmpty()) {
            throw new Exception(PerimeterXErrorCode.START_CALLED_MORE_THAN_ONCE.message$PerimeterX_release());
        }
        String appId = (String) CollectionsKt.L(appIds2);
        Intrinsics.checkNotNullParameter(appId, "appId");
        if (F4.a == null) {
            F4.a = appId;
        }
        if (!k) {
            k = true;
            b = context;
            L4.a = this;
            L4.b = this;
            com.google.firebase.messaging.u uVar = d;
            uVar.b = this;
            uVar.a = this;
            if (Intrinsics.b(Looper.myLooper(), Looper.getMainLooper())) {
                d0.i.f.a(this);
            } else {
                new Handler(Looper.getMainLooper()).post(new RunnableC0131h(24));
            }
        }
        kotlin.coroutines.h hVar = null;
        if (policy.getAllowTouchDetection()) {
            com.perimeterx.mobile_sdk.detections.device.touch_interception.e eVar = com.perimeterx.mobile_sdk.detections.device.touch_interception.e.a;
            com.perimeterx.mobile_sdk.detections.device.touch_interception.e.b = this;
            Intrinsics.checkNotNullParameter(appIds2, "appIds");
            E.D(kotlin.coroutines.n.a, new com.perimeterx.mobile_sdk.detections.device.motion_interception.f(appIds2, hVar, i2));
            Intrinsics.checkNotNullParameter(context, "application");
            com.perimeterx.mobile_sdk.detections.device.touch_interception.e.c = true;
            context.registerActivityLifecycleCallbacks(eVar);
            if (policy.getAllowDeviceMotionDetection()) {
                com.perimeterx.mobile_sdk.detections.device.motion_interception.g gVar = com.perimeterx.mobile_sdk.detections.device.motion_interception.g.a;
                Intrinsics.checkNotNullParameter(appIds2, "appIds");
                E.D(kotlin.coroutines.n.a, new com.perimeterx.mobile_sdk.detections.device.motion_interception.f(appIds2, hVar, 0));
                Intrinsics.checkNotNullParameter(context, "application");
                Object systemService = context.getSystemService("sensor");
                Intrinsics.e(systemService, "null cannot be cast to non-null type android.hardware.SensorManager");
                com.perimeterx.mobile_sdk.detections.device.motion_interception.g.c = (SensorManager) systemService;
                com.perimeterx.mobile_sdk.detections.device.motion_interception.g.b();
            }
        }
        PXStorageMethod storageMethod = policy.getStorageMethod();
        int[] iArr = e.a;
        int i3 = iArr[storageMethod.ordinal()];
        if (i3 == 1) {
            storageType = com.perimeterx.mobile_sdk.local_data.c.a;
        } else {
            if (i3 != 2) {
                throw new NoWhenBranchMatchedException();
            }
            storageType = com.perimeterx.mobile_sdk.local_data.c.b;
        }
        Intrinsics.checkNotNullParameter(storageType, "storageType");
        Intrinsics.checkNotNullParameter(context, "application");
        com.perimeterx.mobile_sdk.local_data.w.b = context;
        int iOrdinal = storageType.ordinal();
        if (iOrdinal == 0) {
            aVar = new com.perimeterx.mobile_sdk.local_data.a(context);
        } else {
            if (iOrdinal != 1) {
                throw new NoWhenBranchMatchedException();
            }
            aVar = new com.perimeterx.mobile_sdk.local_data.v(context);
        }
        com.perimeterx.mobile_sdk.local_data.w.c = aVar;
        aVar.d(true, com.perimeterx.mobile_sdk.local_data.x.a, "PXSDK");
        int i4 = iArr[policy.getStorageMethod().ordinal()];
        if (i4 == 1) {
            Intrinsics.checkNotNullParameter(appIds2, "appIds");
            com.perimeterx.mobile_sdk.local_data.b bVar = com.perimeterx.mobile_sdk.local_data.w.c;
            if (bVar == null) {
                Intrinsics.m("storage");
                throw null;
            }
            if (bVar instanceof com.perimeterx.mobile_sdk.local_data.a) {
                Application application2 = com.perimeterx.mobile_sdk.local_data.w.b;
                if (application2 == null) {
                    Intrinsics.m("application");
                    throw null;
                }
                com.perimeterx.mobile_sdk.local_data.w.b(new com.perimeterx.mobile_sdk.local_data.v(application2), appIds2);
            }
        } else {
            if (i4 != 2) {
                throw new NoWhenBranchMatchedException();
            }
            Intrinsics.checkNotNullParameter(appIds2, "appIds");
            com.perimeterx.mobile_sdk.local_data.b bVar2 = com.perimeterx.mobile_sdk.local_data.w.c;
            if (bVar2 == null) {
                Intrinsics.m("storage");
                throw null;
            }
            if (bVar2 instanceof com.perimeterx.mobile_sdk.local_data.v) {
                Application application3 = com.perimeterx.mobile_sdk.local_data.w.b;
                if (application3 == null) {
                    Intrinsics.m("application");
                    throw null;
                }
                com.perimeterx.mobile_sdk.local_data.w.b(new com.perimeterx.mobile_sdk.local_data.a(application3), appIds2);
            }
        }
        com.perimeterx.mobile_sdk.exception_handler.b bVar3 = com.perimeterx.mobile_sdk.exception_handler.b.a;
        String appId2 = (String) CollectionsKt.L(appIds2);
        Intrinsics.checkNotNullParameter(appId2, "appId");
        if (!com.perimeterx.mobile_sdk.exception_handler.b.c) {
            com.perimeterx.mobile_sdk.exception_handler.b.c = true;
            com.perimeterx.mobile_sdk.exception_handler.b.b = appId2;
            com.perimeterx.mobile_sdk.exception_handler.b.f = Thread.getDefaultUncaughtExceptionHandler();
            Thread.setDefaultUncaughtExceptionHandler(bVar3);
        }
        if (!com.perimeterx.mobile_sdk.exception_handler.b.e) {
            com.perimeterx.mobile_sdk.exception_handler.b.e = true;
            String appId3 = com.perimeterx.mobile_sdk.exception_handler.b.b;
            if (appId3 != null) {
                com.perimeterx.mobile_sdk.local_data.x key = com.perimeterx.mobile_sdk.local_data.x.e;
                Intrinsics.checkNotNullParameter(key, "key");
                Intrinsics.checkNotNullParameter(appId3, "appId");
                com.perimeterx.mobile_sdk.local_data.b bVar4 = com.perimeterx.mobile_sdk.local_data.w.c;
                if (bVar4 == null) {
                    Intrinsics.m("storage");
                    throw null;
                }
                String strA = bVar4.a(key, appId3);
                if (strA != null && strA.length() > 0 && (application = b) != null) {
                    E.A(E.c(O.a), null, null, new com.perimeterx.mobile_sdk.exception_handler.a(appId3, strA, new com.quizlet.data.interactor.set.c((m) null, new androidx.camera.camera2.internal.compat.workaround.a()).b(application), AbstractC3744v4.a(application), null), 3);
                }
            }
        }
        if (policy.getDoctorCheckEnabled()) {
            String appId4 = (String) CollectionsKt.L(appIds2);
            Intrinsics.checkNotNullParameter(appId4, "appId");
            Intrinsics.checkNotNullParameter(context, "context");
            Intrinsics.checkNotNullParameter(policy, "policy");
            if (androidx.constraintlayout.core.widgets.analyzer.f.j == null) {
                androidx.constraintlayout.core.widgets.analyzer.f.j = new androidx.constraintlayout.core.widgets.analyzer.f(appId4, context, policy);
            }
            Intrinsics.d(androidx.constraintlayout.core.widgets.analyzer.f.j);
            com.perimeterx.mobile_sdk.local_data.x key2 = com.perimeterx.mobile_sdk.local_data.x.b;
            Intrinsics.checkNotNullParameter(key2, "key");
            Intrinsics.checkNotNullParameter(appId4, "appId");
            com.perimeterx.mobile_sdk.local_data.b bVar5 = com.perimeterx.mobile_sdk.local_data.w.c;
            if (bVar5 == null) {
                Intrinsics.m("storage");
                throw null;
            }
            bVar5.c("", key2, appId4);
            Intrinsics.d(androidx.constraintlayout.core.widgets.analyzer.f.j);
            com.perimeterx.mobile_sdk.local_data.x key3 = com.perimeterx.mobile_sdk.local_data.x.f;
            Intrinsics.checkNotNullParameter(key3, "key");
            Intrinsics.checkNotNullParameter(appId4, "appId");
            com.perimeterx.mobile_sdk.local_data.b bVar6 = com.perimeterx.mobile_sdk.local_data.w.c;
            if (bVar6 == null) {
                Intrinsics.m("storage");
                throw null;
            }
            bVar6.c("", key3, appId4);
            com.perimeterx.mobile_sdk.local_data.x key4 = com.perimeterx.mobile_sdk.local_data.x.g;
            Intrinsics.checkNotNullParameter(key4, "key");
            Intrinsics.checkNotNullParameter(appId4, "appId");
            com.perimeterx.mobile_sdk.local_data.b bVar7 = com.perimeterx.mobile_sdk.local_data.w.c;
            if (bVar7 == null) {
                Intrinsics.m("storage");
                throw null;
            }
            bVar7.c("", key4, appId4);
        }
        Iterator it3 = appIds2.iterator();
        Intrinsics.checkNotNullExpressionValue(it3, "iterator(...)");
        while (it3.hasNext()) {
            Object next2 = it3.next();
            Intrinsics.checkNotNullExpressionValue(next2, "next(...)");
            String appId5 = (String) next2;
            d dVar = new d(context, this);
            E.D(kotlin.coroutines.n.a, new a(dVar, null, 3));
            Intrinsics.checkNotNullParameter(appId5, "appId");
            Intrinsics.checkNotNullParameter(policy, "policy");
            m mVar = dVar.b;
            mVar.getClass();
            Intrinsics.checkNotNullParameter(appId5, "<set-?>");
            mVar.a = appId5;
            mVar.c = perimeterXDelegate;
            PXPolicy pXPolicyCopy$PerimeterX_release = policy.copy$PerimeterX_release();
            Intrinsics.checkNotNullParameter(pXPolicyCopy$PerimeterX_release, "<set-?>");
            mVar.b = pXPolicyCopy$PerimeterX_release;
            dVar.q();
            if (A4.a(dVar.e)) {
                E.A(E.c(O.a), null, null, new n(dVar, null, 6), 3);
            }
        }
    }

    @Override // androidx.lifecycle.InterfaceC1250k
    public final void onCreate(androidx.lifecycle.J owner) {
        Intrinsics.checkNotNullParameter(owner, "owner");
    }

    @Override // androidx.lifecycle.InterfaceC1250k
    public final void onDestroy(androidx.lifecycle.J owner) {
        Intrinsics.checkNotNullParameter(owner, "owner");
    }

    @Override // androidx.lifecycle.InterfaceC1250k
    public final void onPause(androidx.lifecycle.J owner) {
        Intrinsics.checkNotNullParameter(owner, "owner");
    }

    @Override // androidx.lifecycle.InterfaceC1250k
    public final void onResume(androidx.lifecycle.J owner) {
        Intrinsics.checkNotNullParameter(owner, "owner");
    }

    @Override // androidx.lifecycle.InterfaceC1250k
    public final void onStart(androidx.lifecycle.J owner) throws Throwable {
        m mVar;
        PXPolicy pXPolicy;
        int i2 = 2;
        int i3 = 0;
        int i4 = 1;
        Intrinsics.checkNotNullParameter(owner, "owner");
        if (f == null) {
            Timer timer = new Timer();
            f = timer;
            com.perimeterx.mobile_sdk.detections.device.touch_interception.b bVar = new com.perimeterx.mobile_sdk.detections.device.touch_interception.b(i4);
            String str = com.perimeterx.mobile_sdk.configurations.i.a;
            timer.schedule(bVar, 300000L, 300000L);
        }
        J j2 = new J();
        kotlin.coroutines.h hVar = null;
        E.D(kotlin.coroutines.n.a, new f(j2, hVar, i3));
        Iterator it2 = ((ArrayList) j2.a).iterator();
        Intrinsics.checkNotNullExpressionValue(it2, "iterator(...)");
        while (it2.hasNext()) {
            Object next = it2.next();
            Intrinsics.checkNotNullExpressionValue(next, "next(...)");
            d dVar = (d) next;
            dVar.getClass();
            E.A(E.c(O.a), null, null, new n(dVar, hVar, i2), 3);
            m mVar2 = dVar.b;
            com.perimeterx.mobile_sdk.block.b bVar2 = mVar2.j;
            if (bVar2 != null) {
                mVar2.j = null;
                dVar.f.b(bVar2, dVar.r());
            }
        }
        d dVarA = a(null);
        if (dVarA == null || (mVar = dVarA.b) == null || (pXPolicy = mVar.b) == null || !pXPolicy.getAllowTouchDetection()) {
            return;
        }
        if (com.perimeterx.mobile_sdk.detections.device.touch_interception.e.c) {
            com.perimeterx.mobile_sdk.detections.device.touch_interception.e.g = D1.a(10, 6, null);
            E.A(com.perimeterx.mobile_sdk.detections.device.touch_interception.e.f, null, null, new com.perimeterx.mobile_sdk.detections.device.motion_interception.b(i2, i4, hVar), 3);
            E.D(kotlin.coroutines.n.a, new com.perimeterx.mobile_sdk.detections.device.touch_interception.d(i2, i3, hVar));
            com.perimeterx.mobile_sdk.detections.device.touch_interception.e.b();
            com.perimeterx.mobile_sdk.detections.device.touch_interception.e.c(com.perimeterx.mobile_sdk.detections.device.touch_interception.f.a);
            com.quizlet.data.interactor.school.b bVar3 = com.perimeterx.mobile_sdk.detections.device.touch_interception.e.e;
            com.perimeterx.mobile_sdk.detections.device.touch_interception.g gVar = com.perimeterx.mobile_sdk.detections.device.touch_interception.g.b;
            bVar3.getClass();
            Intrinsics.checkNotNullParameter(gVar, "<set-?>");
        }
        if (pXPolicy.getAllowDeviceMotionDetection()) {
            com.perimeterx.mobile_sdk.detections.device.motion_interception.g.b();
        }
    }

    @Override // androidx.lifecycle.InterfaceC1250k
    public final void onStop(androidx.lifecycle.J owner) throws Throwable {
        m mVar;
        PXPolicy pXPolicy;
        Intrinsics.checkNotNullParameter(owner, "owner");
        Timer timer = f;
        if (timer != null) {
            timer.cancel();
        }
        kotlin.coroutines.h hVar = null;
        f = null;
        J j2 = new J();
        E.D(kotlin.coroutines.n.a, new f(j2, hVar, 0));
        Iterator it2 = ((ArrayList) j2.a).iterator();
        Intrinsics.checkNotNullExpressionValue(it2, "iterator(...)");
        while (it2.hasNext()) {
            Object next = it2.next();
            Intrinsics.checkNotNullExpressionValue(next, "next(...)");
            d dVar = (d) next;
            dVar.getClass();
            E.A(E.c(O.a), null, null, new n(dVar, hVar, 3), 3);
        }
        d dVarA = a(null);
        if (dVarA == null || (mVar = dVarA.b) == null || (pXPolicy = mVar.b) == null || !pXPolicy.getAllowTouchDetection()) {
            return;
        }
        try {
            Timer timer2 = com.perimeterx.mobile_sdk.detections.device.touch_interception.e.d;
            if (timer2 != null) {
                timer2.cancel();
            }
        } catch (Exception unused) {
        }
        com.perimeterx.mobile_sdk.detections.device.touch_interception.e.d = null;
        kotlinx.coroutines.channels.h hVar2 = com.perimeterx.mobile_sdk.detections.device.touch_interception.e.g;
        if (hVar2 != null) {
            hVar2.i(null);
        }
        com.perimeterx.mobile_sdk.detections.device.touch_interception.e.g = null;
        com.quizlet.data.interactor.school.b bVar = com.perimeterx.mobile_sdk.detections.device.touch_interception.e.e;
        com.perimeterx.mobile_sdk.detections.device.touch_interception.g gVar = com.perimeterx.mobile_sdk.detections.device.touch_interception.g.a;
        bVar.getClass();
        Intrinsics.checkNotNullParameter(gVar, "<set-?>");
        if (pXPolicy.getAllowDeviceMotionDetection()) {
            com.perimeterx.mobile_sdk.detections.device.motion_interception.g.a.c();
        }
    }
}
