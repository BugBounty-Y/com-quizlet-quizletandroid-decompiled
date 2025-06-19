package com.perimeterx.mobile_sdk.session;

import android.app.Application;
import android.os.Handler;
import android.os.Looper;
import com.perimeterx.mobile_sdk.PerimeterXDelegate;
import com.perimeterx.mobile_sdk.main.PXPolicyUrlRequestInterceptionType;
import java.net.URL;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Timer;
import java.util.concurrent.locks.ReentrantLock;
import kotlin.NoWhenBranchMatchedException;
import kotlin.collections.B;
import kotlin.collections.CollectionsKt;
import kotlin.collections.F;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;
import kotlinx.coroutines.E;
import kotlinx.coroutines.O;

/* loaded from: classes2.dex */
public final class d {
    public final l a;
    public final m b;
    public final ArrayList c;
    public final kotlinx.coroutines.sync.c d;
    public final Application e;
    public final com.perimeterx.mobile_sdk.block.a f;
    public final com.google.mlkit.common.sdkinternal.model.a g;
    public final androidx.work.impl.model.v h;
    public final com.perimeterx.mobile_sdk.local_data.w i;
    public final ArrayList j;
    public Timer k;

    public d(Application context, l lVar) {
        com.perimeterx.mobile_sdk.block.a blockManager = new com.perimeterx.mobile_sdk.block.a();
        com.google.mlkit.common.sdkinternal.model.a businessLogicManager = new com.google.mlkit.common.sdkinternal.model.a(22);
        androidx.work.impl.model.v detectionsManager = new androidx.work.impl.model.v(context);
        com.perimeterx.mobile_sdk.local_data.w localDataManager = com.perimeterx.mobile_sdk.local_data.w.a;
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(blockManager, "blockManager");
        Intrinsics.checkNotNullParameter(businessLogicManager, "businessLogicManager");
        Intrinsics.checkNotNullParameter(detectionsManager, "detectionsManager");
        Intrinsics.checkNotNullParameter(localDataManager, "localDataManager");
        this.b = new m();
        this.c = new ArrayList();
        this.d = kotlinx.coroutines.sync.d.a();
        this.j = new ArrayList();
        this.e = context;
        this.a = lVar;
        this.f = blockManager;
        blockManager.a = this;
        this.g = businessLogicManager;
        this.h = detectionsManager;
        this.i = localDataManager;
    }

    /* JADX WARN: Code restructure failed: missing block: B:24:0x006f, code lost:
    
        if (r5.e(r0) == r1) goto L25;
     */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object d(com.perimeterx.mobile_sdk.session.d r5, com.perimeterx.mobile_sdk.models.a r6, kotlin.coroutines.jvm.internal.c r7) {
        /*
            boolean r0 = r7 instanceof com.perimeterx.mobile_sdk.session.v
            if (r0 == 0) goto L13
            r0 = r7
            com.perimeterx.mobile_sdk.session.v r0 = (com.perimeterx.mobile_sdk.session.v) r0
            int r1 = r0.o
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.o = r1
            goto L18
        L13:
            com.perimeterx.mobile_sdk.session.v r0 = new com.perimeterx.mobile_sdk.session.v
            r0.<init>(r5, r7)
        L18:
            java.lang.Object r7 = r0.m
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.o
            r3 = 2
            r4 = 1
            if (r2 == 0) goto L3e
            if (r2 == r4) goto L32
            if (r2 != r3) goto L2a
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L72
        L2a:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L32:
            kotlinx.coroutines.sync.c r5 = r0.l
            com.perimeterx.mobile_sdk.models.a r6 = r0.k
            com.perimeterx.mobile_sdk.session.d r2 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r7)
            r7 = r5
            r5 = r2
            goto L52
        L3e:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            r0.j = r5
            r0.k = r6
            kotlinx.coroutines.sync.c r7 = r5.d
            r0.l = r7
            r0.o = r4
            java.lang.Object r2 = r7.d(r0)
            if (r2 != r1) goto L52
            goto L71
        L52:
            r2 = 0
            com.perimeterx.mobile_sdk.session.m r4 = r5.b     // Catch: java.lang.Throwable -> L75
            java.util.ArrayList r4 = r4.m     // Catch: java.lang.Throwable -> L75
            r4.add(r6)     // Catch: java.lang.Throwable -> L75
            r7.f(r2)
            com.perimeterx.mobile_sdk.session.m r6 = r5.b
            boolean r6 = r6.d
            if (r6 == 0) goto L72
            r0.j = r2
            r0.k = r2
            r0.l = r2
            r0.o = r3
            java.lang.Object r5 = r5.e(r0)
            if (r5 != r1) goto L72
        L71:
            return r1
        L72:
            kotlin.Unit r5 = kotlin.Unit.a
            return r5
        L75:
            r5 = move-exception
            r7.f(r2)
            throw r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.perimeterx.mobile_sdk.session.d.d(com.perimeterx.mobile_sdk.session.d, com.perimeterx.mobile_sdk.models.a, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:49:0x018a  */
    /* JADX WARN: Removed duplicated region for block: B:53:0x0191  */
    /* JADX WARN: Removed duplicated region for block: B:60:0x01a6  */
    /* JADX WARN: Removed duplicated region for block: B:62:0x01a9 A[RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:63:0x01aa  */
    /* JADX WARN: Removed duplicated region for block: B:78:0x0229  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0019  */
    /* JADX WARN: Removed duplicated region for block: B:81:0x022e  */
    /* JADX WARN: Removed duplicated region for block: B:88:0x0242  */
    /* JADX WARN: Removed duplicated region for block: B:90:0x0245 A[RETURN] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object a(com.perimeterx.mobile_sdk.api_data.j r25, java.lang.String r26, com.perimeterx.mobile_sdk.detections.a r27, kotlin.coroutines.jvm.internal.c r28) throws java.lang.Exception {
        /*
            Method dump skipped, instructions count: 606
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.perimeterx.mobile_sdk.session.d.a(com.perimeterx.mobile_sdk.api_data.j, java.lang.String, com.perimeterx.mobile_sdk.detections.a, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:57:0x00d1 A[Catch: Exception -> 0x003a, TryCatch #0 {Exception -> 0x003a, blocks: (B:14:0x0035, B:55:0x00c8, B:57:0x00d1, B:58:0x00db, B:60:0x00df, B:66:0x0100, B:21:0x0047, B:24:0x0050, B:41:0x0091, B:43:0x00a7, B:46:0x00ae, B:51:0x00ba, B:62:0x00f2, B:27:0x0058, B:37:0x007e, B:34:0x006c, B:36:0x0074), top: B:84:0x002b }] */
    /* JADX WARN: Removed duplicated region for block: B:60:0x00df A[Catch: Exception -> 0x003a, TryCatch #0 {Exception -> 0x003a, blocks: (B:14:0x0035, B:55:0x00c8, B:57:0x00d1, B:58:0x00db, B:60:0x00df, B:66:0x0100, B:21:0x0047, B:24:0x0050, B:41:0x0091, B:43:0x00a7, B:46:0x00ae, B:51:0x00ba, B:62:0x00f2, B:27:0x0058, B:37:0x007e, B:34:0x006c, B:36:0x0074), top: B:84:0x002b }] */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0018  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object b(com.perimeterx.mobile_sdk.api_data.j r17, kotlin.coroutines.jvm.internal.c r18) throws java.lang.Exception {
        /*
            Method dump skipped, instructions count: 315
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.perimeterx.mobile_sdk.session.d.b(com.perimeterx.mobile_sdk.api_data.j, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Code restructure failed: missing block: B:57:0x012a, code lost:
    
        if (r13 != r1) goto L59;
     */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object c(com.perimeterx.mobile_sdk.block.b r11, java.lang.String r12, kotlin.coroutines.jvm.internal.c r13) {
        /*
            Method dump skipped, instructions count: 315
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.perimeterx.mobile_sdk.session.d.c(com.perimeterx.mobile_sdk.block.b, java.lang.String, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:104:0x0200  */
    /* JADX WARN: Removed duplicated region for block: B:106:0x020f  */
    /* JADX WARN: Removed duplicated region for block: B:46:0x00d7  */
    /* JADX WARN: Removed duplicated region for block: B:50:0x00f8 A[Catch: all -> 0x00fc, Exception -> 0x0101, TryCatch #5 {Exception -> 0x0101, all -> 0x00fc, blocks: (B:48:0x00eb, B:50:0x00f8, B:56:0x0107, B:58:0x0143, B:60:0x014d, B:62:0x0155, B:63:0x0157, B:65:0x015b, B:67:0x0163, B:68:0x0165, B:70:0x0169, B:72:0x016f, B:75:0x0176, B:77:0x017e, B:79:0x0182, B:81:0x0188, B:82:0x018b), top: B:116:0x00eb }] */
    /* JADX WARN: Removed duplicated region for block: B:55:0x0106  */
    /* JADX WARN: Removed duplicated region for block: B:58:0x0143 A[Catch: all -> 0x00fc, Exception -> 0x0101, TryCatch #5 {Exception -> 0x0101, all -> 0x00fc, blocks: (B:48:0x00eb, B:50:0x00f8, B:56:0x0107, B:58:0x0143, B:60:0x014d, B:62:0x0155, B:63:0x0157, B:65:0x015b, B:67:0x0163, B:68:0x0165, B:70:0x0169, B:72:0x016f, B:75:0x0176, B:77:0x017e, B:79:0x0182, B:81:0x0188, B:82:0x018b), top: B:116:0x00eb }] */
    /* JADX WARN: Removed duplicated region for block: B:7:0x001a  */
    /* JADX WARN: Removed duplicated region for block: B:85:0x019e  */
    /* JADX WARN: Removed duplicated region for block: B:88:0x01ab  */
    /* JADX WARN: Removed duplicated region for block: B:91:0x01c0 A[Catch: all -> 0x003b, TryCatch #1 {all -> 0x003b, blocks: (B:14:0x0034, B:89:0x01b0, B:91:0x01c0, B:93:0x01c4, B:95:0x01d5), top: B:111:0x0034 }] */
    /* JADX WARN: Removed duplicated region for block: B:95:0x01d5 A[Catch: all -> 0x003b, TRY_LEAVE, TryCatch #1 {all -> 0x003b, blocks: (B:14:0x0034, B:89:0x01b0, B:91:0x01c0, B:93:0x01c4, B:95:0x01d5), top: B:111:0x0034 }] */
    /* JADX WARN: Removed duplicated region for block: B:98:0x01e2  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object e(kotlin.coroutines.jvm.internal.c r26) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 536
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.perimeterx.mobile_sdk.session.d.e(kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r16v0, types: [java.lang.Throwable] */
    public final ArrayList f(String url) {
        ArrayList arrayList;
        ArrayList arrayListF;
        ArrayList arrayList2;
        Intrinsics.checkNotNullParameter(url, "url");
        ArrayList arrayList3 = null;
        com.perimeterx.mobile_sdk.detections.device.a deviceInfo = new com.quizlet.data.interactor.set.c((m) null, new androidx.camera.camera2.internal.compat.workaround.a()).b(this.e);
        this.g.getClass();
        Intrinsics.checkNotNullParameter(url, "url");
        m session = this.b;
        Intrinsics.checkNotNullParameter(session, "session");
        Intrinsics.checkNotNullParameter(deviceInfo, "deviceInfo");
        ArrayList arrayList4 = new ArrayList();
        com.perimeterx.mobile_sdk.web_view_interception.a[] aVarArrValues = com.perimeterx.mobile_sdk.web_view_interception.a.values();
        int length = aVarArrValues.length;
        int i = 0;
        while (i < length) {
            com.perimeterx.mobile_sdk.web_view_interception.a aVar = aVarArrValues[i];
            com.perimeterx.mobile_sdk.models.f fVar = session.g;
            if (fVar != null) {
                ReentrantLock reentrantLock = fVar.d;
                reentrantLock.lock();
                arrayList = new ArrayList(fVar.c);
                reentrantLock.unlock();
            } else {
                arrayList = arrayList3;
            }
            int iOrdinal = aVar.ordinal();
            ?? r16 = arrayList3;
            if (iOrdinal == 0) {
                arrayListF = B.f("_pxvid");
            } else if (iOrdinal != 1) {
                if (iOrdinal == 2) {
                    arrayListF = B.f("_pxwvm");
                } else {
                    if (iOrdinal != 3) {
                        throw new NoWhenBranchMatchedException();
                    }
                    arrayListF = B.f("_pxhd");
                }
            } else if (arrayList != null) {
                com.perimeterx.mobile_sdk.web_view_interception.a.a.getClass();
                arrayListF = new ArrayList();
                Iterator it2 = arrayList.iterator();
                Intrinsics.checkNotNullExpressionValue(it2, "iterator(...)");
                while (it2.hasNext()) {
                    Object next = it2.next();
                    Intrinsics.checkNotNullExpressionValue(next, "next(...)");
                    arrayListF.add(((com.perimeterx.mobile_sdk.models.d) next).a);
                }
            } else {
                arrayListF = new ArrayList();
            }
            int iOrdinal2 = aVar.ordinal();
            if (iOrdinal2 == 0) {
                com.perimeterx.mobile_sdk.local_data.x key = com.perimeterx.mobile_sdk.local_data.x.b;
                String appId = session.a;
                Intrinsics.checkNotNullParameter(key, "key");
                Intrinsics.checkNotNullParameter(appId, "appId");
                com.perimeterx.mobile_sdk.local_data.b bVar = com.perimeterx.mobile_sdk.local_data.w.c;
                if (bVar == null) {
                    Intrinsics.m("storage");
                    throw r16;
                }
                String strA = bVar.a(key, appId);
                if (strA == null) {
                    strA = r16;
                }
                arrayList2 = (strA == null || strA.length() == 0) ? new ArrayList() : B.f(strA);
            } else if (iOrdinal2 == 1) {
                com.perimeterx.mobile_sdk.models.f fVar2 = session.g;
                if (fVar2 != null) {
                    ReentrantLock reentrantLock2 = fVar2.d;
                    reentrantLock2.lock();
                    ArrayList arrayList5 = new ArrayList(fVar2.c);
                    reentrantLock2.unlock();
                    com.perimeterx.mobile_sdk.web_view_interception.a.a.getClass();
                    arrayList2 = new ArrayList();
                    Iterator it3 = arrayList5.iterator();
                    Intrinsics.checkNotNullExpressionValue(it3, "iterator(...)");
                    while (it3.hasNext()) {
                        Object next2 = it3.next();
                        Intrinsics.checkNotNullExpressionValue(next2, "next(...)");
                        arrayList2.add(((com.perimeterx.mobile_sdk.models.d) next2).b);
                    }
                } else {
                    arrayList2 = new ArrayList();
                }
            } else if (iOrdinal2 == 2) {
                arrayList2 = B.f("1");
            } else {
                if (iOrdinal2 != 3) {
                    throw new NoWhenBranchMatchedException();
                }
                arrayList2 = B.f("");
            }
            if (arrayListF.size() == arrayList2.size()) {
                int size = arrayListF.size();
                for (int i2 = 0; i2 < size; i2++) {
                    Object obj = arrayListF.get(i2);
                    Intrinsics.checkNotNullExpressionValue(obj, "get(...)");
                    Object obj2 = arrayList2.get(i2);
                    Intrinsics.checkNotNullExpressionValue(obj2, "get(...)");
                    arrayList4.add(com.google.mlkit.common.sdkinternal.model.a.l(url, (String) obj, (String) obj2));
                }
            }
            i++;
            arrayList3 = r16;
        }
        return arrayList4;
    }

    public final void g(com.perimeterx.mobile_sdk.models.f fVar) {
        com.perimeterx.mobile_sdk.models.d dVar;
        m mVar = this.b;
        mVar.g = fVar;
        mVar.h = assistantMode.refactored.a.f();
        kotlin.coroutines.h hVar = null;
        if (fVar != null) {
            ReentrantLock reentrantLock = fVar.d;
            reentrantLock.lock();
            ArrayList arrayList = new ArrayList(fVar.c);
            reentrantLock.unlock();
            if (arrayList.isEmpty()) {
                dVar = null;
            } else {
                if (arrayList.size() > 1) {
                    F.t(arrayList, new com.google.zxing.aztec.encoder.c(5));
                }
                dVar = (com.perimeterx.mobile_sdk.models.d) CollectionsKt.U(arrayList);
            }
            if (dVar != null) {
                StringBuilder sb = new StringBuilder();
                com.perimeterx.mobile_sdk.models.e.a.getClass();
                com.perimeterx.mobile_sdk.models.e eVarH = com.google.android.material.shape.e.h(dVar.a);
                sb.append(eVarH != null ? eVarH.a() : -1);
                sb.append(':');
                sb.append(dVar.b);
                String string = sb.toString();
                com.perimeterx.mobile_sdk.local_data.x xVar = com.perimeterx.mobile_sdk.local_data.x.c;
                String str = mVar.a;
                this.i.getClass();
                com.perimeterx.mobile_sdk.local_data.w.c(string, xVar, str);
                q();
            }
        }
        new Handler(Looper.getMainLooper()).post(new com.google.firebase.crashlytics.internal.common.i(15, this, this));
        E.A(E.c(O.a), null, null, new n(this, hVar, 4), 3);
    }

    public final boolean h(URL url, com.perimeterx.mobile_sdk.business_logic.b source) {
        Intrinsics.checkNotNullParameter(url, "url");
        Intrinsics.checkNotNullParameter(source, "source");
        this.g.getClass();
        Intrinsics.checkNotNullParameter(url, "url");
        m session = this.b;
        Intrinsics.checkNotNullParameter(session, "session");
        Intrinsics.checkNotNullParameter(source, "source");
        String host = url.getHost();
        Intrinsics.checkNotNullExpressionValue(host, "getHost(...)");
        String str = com.perimeterx.mobile_sdk.configurations.i.a;
        if (!StringsKt.G(host, "perimeterx.net", false) && (source != com.perimeterx.mobile_sdk.business_logic.b.a || session.b.getUrlRequestInterceptionType() != PXPolicyUrlRequestInterceptionType.NONE)) {
            ArrayList<String> arrayListDomains$PerimeterX_release = session.b.domains$PerimeterX_release(session.a);
            if (arrayListDomains$PerimeterX_release.isEmpty()) {
                return true;
            }
            Iterator<String> it2 = arrayListDomains$PerimeterX_release.iterator();
            Intrinsics.checkNotNullExpressionValue(it2, "iterator(...)");
            while (it2.hasNext()) {
                String next = it2.next();
                Intrinsics.checkNotNullExpressionValue(next, "next(...)");
                String str2 = next;
                String host2 = url.getHost();
                Intrinsics.checkNotNullExpressionValue(host2, "getHost(...)");
                if (Intrinsics.b(StringsKt.E(host2, str2), str2)) {
                    return true;
                }
            }
        }
        return false;
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object i(com.perimeterx.mobile_sdk.api_data.j r5, java.lang.String r6, com.perimeterx.mobile_sdk.detections.a r7, kotlin.coroutines.jvm.internal.c r8) throws java.lang.Exception {
        /*
            r4 = this;
            boolean r0 = r8 instanceof com.perimeterx.mobile_sdk.session.u
            if (r0 == 0) goto L13
            r0 = r8
            com.perimeterx.mobile_sdk.session.u r0 = (com.perimeterx.mobile_sdk.session.u) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.perimeterx.mobile_sdk.session.u r0 = new com.perimeterx.mobile_sdk.session.u
            r0.<init>(r4, r8)
        L18:
            java.lang.Object r8 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L31
            if (r2 != r3) goto L29
            androidx.glance.appwidget.protobuf.Z.e(r8)     // Catch: java.lang.Exception -> L27
            goto L4d
        L27:
            r5 = move-exception
            goto L3d
        L29:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L31:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            r0.l = r3     // Catch: java.lang.Exception -> L27
            java.lang.Object r5 = r4.a(r5, r6, r7, r0)     // Catch: java.lang.Exception -> L27
            if (r5 != r1) goto L4d
            return r1
        L3d:
            java.lang.String r6 = r5.getMessage()
            com.perimeterx.mobile_sdk.PerimeterXErrorCode r7 = com.perimeterx.mobile_sdk.PerimeterXErrorCode.INTERNAL_ERROR
            java.lang.String r7 = r7.message$PerimeterX_release()
            boolean r6 = kotlin.jvm.internal.Intrinsics.b(r6, r7)
            if (r6 == 0) goto L50
        L4d:
            kotlin.Unit r5 = kotlin.Unit.a
            return r5
        L50:
            throw r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.perimeterx.mobile_sdk.session.d.i(com.perimeterx.mobile_sdk.api_data.j, java.lang.String, com.perimeterx.mobile_sdk.detections.a, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object j(com.perimeterx.mobile_sdk.api_data.j r5, kotlin.coroutines.jvm.internal.c r6) {
        /*
            r4 = this;
            boolean r0 = r6 instanceof com.perimeterx.mobile_sdk.session.w
            if (r0 == 0) goto L13
            r0 = r6
            com.perimeterx.mobile_sdk.session.w r0 = (com.perimeterx.mobile_sdk.session.w) r0
            int r1 = r0.o
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.o = r1
            goto L18
        L13:
            com.perimeterx.mobile_sdk.session.w r0 = new com.perimeterx.mobile_sdk.session.w
            r0.<init>(r4, r6)
        L18:
            java.lang.Object r6 = r0.m
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.o
            r3 = 1
            if (r2 == 0) goto L35
            if (r2 != r3) goto L2d
            kotlinx.coroutines.sync.c r5 = r0.l
            com.perimeterx.mobile_sdk.api_data.j r1 = r0.k
            com.perimeterx.mobile_sdk.session.d r0 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L4c
        L2d:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L35:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            r0.j = r4
            r0.k = r5
            kotlinx.coroutines.sync.c r6 = r4.d
            r0.l = r6
            r0.o = r3
            java.lang.Object r0 = r6.d(r0)
            if (r0 != r1) goto L49
            return r1
        L49:
            r0 = r4
            r1 = r5
            r5 = r6
        L4c:
            r6 = 0
            com.perimeterx.mobile_sdk.session.m r2 = r0.b     // Catch: java.lang.Throwable -> L6a
            java.util.ArrayList r2 = r2.f     // Catch: java.lang.Throwable -> L6a
            r2.add(r1)     // Catch: java.lang.Throwable -> L6a
            r5.f(r6)
            kotlinx.coroutines.scheduling.e r5 = kotlinx.coroutines.O.a
            kotlinx.coroutines.internal.d r5 = kotlinx.coroutines.E.c(r5)
            com.perimeterx.mobile_sdk.session.n r1 = new com.perimeterx.mobile_sdk.session.n
            r2 = 5
            r1.<init>(r0, r6, r2)
            r0 = 3
            kotlinx.coroutines.E.A(r5, r6, r6, r1, r0)
            kotlin.Unit r5 = kotlin.Unit.a
            return r5
        L6a:
            r0 = move-exception
            r5.f(r6)
            throw r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.perimeterx.mobile_sdk.session.d.j(com.perimeterx.mobile_sdk.api_data.j, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Code restructure failed: missing block: B:37:0x00a1, code lost:
    
        if (r9 == r1) goto L41;
     */
    /* JADX WARN: Code restructure failed: missing block: B:40:0x00b0, code lost:
    
        if (r2.k(r0) == r1) goto L41;
     */
    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /* JADX WARN: Type inference failed for: r2v10 */
    /* JADX WARN: Type inference failed for: r2v11 */
    /* JADX WARN: Type inference failed for: r2v6 */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object k(kotlin.coroutines.jvm.internal.c r9) {
        /*
            r8 = this;
            boolean r0 = r9 instanceof com.perimeterx.mobile_sdk.session.y
            if (r0 == 0) goto L13
            r0 = r9
            com.perimeterx.mobile_sdk.session.y r0 = (com.perimeterx.mobile_sdk.session.y) r0
            int r1 = r0.o
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.o = r1
            goto L18
        L13:
            com.perimeterx.mobile_sdk.session.y r0 = new com.perimeterx.mobile_sdk.session.y
            r0.<init>(r8, r9)
        L18:
            java.lang.Object r9 = r0.m
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.o
            r3 = 3
            r4 = 2
            r5 = 1
            r6 = 0
            if (r2 == 0) goto L4a
            if (r2 == r5) goto L3e
            if (r2 == r4) goto L37
            if (r2 != r3) goto L2f
            androidx.glance.appwidget.protobuf.Z.e(r9)
            goto Lb3
        L2f:
            java.lang.IllegalStateException r9 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r9.<init>(r0)
            throw r9
        L37:
            com.perimeterx.mobile_sdk.session.d r2 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r9)     // Catch: java.lang.Exception -> La4
            goto La4
        L3e:
            kotlinx.coroutines.sync.c r2 = r0.l
            kotlin.jvm.internal.J r5 = r0.k
            com.perimeterx.mobile_sdk.session.d r7 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r9)
            r9 = r2
            r2 = r7
            goto L73
        L4a:
            androidx.glance.appwidget.protobuf.Z.e(r9)
            com.perimeterx.mobile_sdk.session.m r9 = r8.b
            com.perimeterx.mobile_sdk.main.PXPolicy r9 = r9.b
            boolean r9 = r9.getAllowTouchDetection()
            if (r9 != 0) goto L5a
            kotlin.Unit r9 = kotlin.Unit.a
            return r9
        L5a:
            kotlin.jvm.internal.J r9 = new kotlin.jvm.internal.J
            r9.<init>()
            r0.j = r8
            r0.k = r9
            kotlinx.coroutines.sync.c r2 = r8.d
            r0.l = r2
            r0.o = r5
            java.lang.Object r5 = r2.d(r0)
            if (r5 != r1) goto L70
            goto Lb2
        L70:
            r5 = r9
            r9 = r2
            r2 = r8
        L73:
            com.perimeterx.mobile_sdk.session.m r7 = r2.b     // Catch: java.lang.Throwable -> L88
            java.util.ArrayList r7 = r7.f     // Catch: java.lang.Throwable -> L88
            boolean r7 = r7.isEmpty()     // Catch: java.lang.Throwable -> L88
            if (r7 != 0) goto L8a
            com.perimeterx.mobile_sdk.session.m r7 = r2.b     // Catch: java.lang.Throwable -> L88
            java.util.ArrayList r7 = r7.f     // Catch: java.lang.Throwable -> L88
            java.lang.Object r7 = kotlin.collections.G.z(r7)     // Catch: java.lang.Throwable -> L88
            r5.a = r7     // Catch: java.lang.Throwable -> L88
            goto L8a
        L88:
            r0 = move-exception
            goto Lb6
        L8a:
            kotlin.Unit r7 = kotlin.Unit.a     // Catch: java.lang.Throwable -> L88
            r9.f(r6)
            java.lang.Object r9 = r5.a
            com.perimeterx.mobile_sdk.api_data.j r9 = (com.perimeterx.mobile_sdk.api_data.j) r9
            if (r9 == 0) goto Lb3
            r0.j = r2     // Catch: java.lang.Exception -> La4
            r0.k = r6     // Catch: java.lang.Exception -> La4
            r0.l = r6     // Catch: java.lang.Exception -> La4
            r0.o = r4     // Catch: java.lang.Exception -> La4
            java.lang.Object r9 = r2.b(r9, r0)     // Catch: java.lang.Exception -> La4
            if (r9 != r1) goto La4
            goto Lb2
        La4:
            r0.j = r6
            r0.k = r6
            r0.l = r6
            r0.o = r3
            java.lang.Object r9 = r2.k(r0)
            if (r9 != r1) goto Lb3
        Lb2:
            return r1
        Lb3:
            kotlin.Unit r9 = kotlin.Unit.a
            return r9
        Lb6:
            r9.f(r6)
            throw r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.perimeterx.mobile_sdk.session.d.k(kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public final ArrayList l(String url) {
        Intrinsics.checkNotNullParameter(url, "url");
        com.perimeterx.mobile_sdk.detections.device.a deviceInfo = new com.quizlet.data.interactor.set.c((m) null, new androidx.camera.camera2.internal.compat.workaround.a()).b(this.e);
        this.g.getClass();
        Intrinsics.checkNotNullParameter(url, "url");
        m session = this.b;
        Intrinsics.checkNotNullParameter(session, "session");
        Intrinsics.checkNotNullParameter(deviceInfo, "deviceInfo");
        try {
            ArrayList arrayList = new ArrayList();
            arrayList.add(com.google.mlkit.common.sdkinternal.model.a.l(url, "_px_mobile_data", com.google.mlkit.common.sdkinternal.model.a.h(session, deviceInfo)));
            return arrayList;
        } catch (Exception unused) {
            return new ArrayList();
        }
    }

    public final void m() {
        E.A(E.c(O.a), null, null, new q(this, true, null), 3);
        m mVar = this.b;
        String str = mVar.a;
        new Handler(Looper.getMainLooper()).post(new c(mVar.c, str, 1));
        androidx.constraintlayout.core.widgets.analyzer.f fVar = androidx.constraintlayout.core.widgets.analyzer.f.j;
        if (fVar == null || !fVar.f()) {
            return;
        }
        com.perimeterx.mobile_sdk.doctor_app.model.b bVar = ((com.perimeterx.mobile_sdk.doctor_app.model.d) fVar.i).e;
        if (bVar != null) {
            bVar.f = true;
        }
        new Handler(Looper.getMainLooper()).post(new com.perimeterx.mobile_sdk.doctor_app.c(fVar, 2));
    }

    /* JADX WARN: Code restructure failed: missing block: B:20:0x004c, code lost:
    
        if (b(r6, r0) == r1) goto L27;
     */
    /* JADX WARN: Code restructure failed: missing block: B:26:0x0060, code lost:
    
        if (r2.n(r0) == r1) goto L27;
     */
    /* JADX WARN: Code restructure failed: missing block: B:27:0x0062, code lost:
    
        return r1;
     */
    /* JADX WARN: Removed duplicated region for block: B:25:0x0057  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object n(kotlin.coroutines.jvm.internal.c r6) {
        /*
            r5 = this;
            boolean r0 = r6 instanceof com.perimeterx.mobile_sdk.session.b
            if (r0 == 0) goto L13
            r0 = r6
            com.perimeterx.mobile_sdk.session.b r0 = (com.perimeterx.mobile_sdk.session.b) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.perimeterx.mobile_sdk.session.b r0 = new com.perimeterx.mobile_sdk.session.b
            r0.<init>(r5, r6)
        L18:
            java.lang.Object r6 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 2
            r4 = 1
            if (r2 == 0) goto L38
            if (r2 == r4) goto L32
            if (r2 != r3) goto L2a
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L63
        L2a:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r0)
            throw r6
        L32:
            com.perimeterx.mobile_sdk.session.d r2 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r6)     // Catch: java.lang.Exception -> L50
            goto L63
        L38:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            com.perimeterx.mobile_sdk.session.m r6 = r5.b
            int r2 = r6.e
            int r2 = r2 + r4
            r6.e = r2
            com.perimeterx.mobile_sdk.api_data.j r6 = com.perimeterx.mobile_sdk.api_data.j.a     // Catch: java.lang.Exception -> L4f
            r0.j = r5     // Catch: java.lang.Exception -> L4f
            r0.m = r4     // Catch: java.lang.Exception -> L4f
            java.lang.Object r6 = r5.b(r6, r0)     // Catch: java.lang.Exception -> L4f
            if (r6 != r1) goto L63
            goto L62
        L4f:
            r2 = r5
        L50:
            com.perimeterx.mobile_sdk.session.m r6 = r2.b
            int r6 = r6.e
            r4 = 3
            if (r6 >= r4) goto L63
            r6 = 0
            r0.j = r6
            r0.m = r3
            java.lang.Object r6 = r2.n(r0)
            if (r6 != r1) goto L63
        L62:
            return r1
        L63:
            kotlin.Unit r6 = kotlin.Unit.a
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: com.perimeterx.mobile_sdk.session.d.n(kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:49:0x0166  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.util.LinkedHashMap o() {
        /*
            Method dump skipped, instructions count: 537
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.perimeterx.mobile_sdk.session.d.o():java.util.LinkedHashMap");
    }

    public final void p(String url) {
        Intrinsics.checkNotNullParameter(url, "url");
        com.perimeterx.mobile_sdk.local_data.x xVar = com.perimeterx.mobile_sdk.local_data.x.f;
        String str = this.b.a;
        this.i.getClass();
        String strA = com.perimeterx.mobile_sdk.local_data.w.a(xVar, str);
        if (strA == null || strA.length() <= 0) {
            return;
        }
        kotlin.coroutines.h hVar = null;
        E.D(kotlin.coroutines.n.a, new j(this, url, hVar, 1));
        E.D(kotlin.coroutines.n.a, new a(this, hVar, 1));
    }

    public final void q() {
        m mVar = this.b;
        String str = mVar.a;
        PerimeterXDelegate perimeterXDelegate = mVar.c;
        LinkedHashMap linkedHashMapO = o();
        if (Intrinsics.b(mVar.l, linkedHashMapO)) {
            return;
        }
        Intrinsics.checkNotNullParameter(linkedHashMapO, "<set-?>");
        mVar.l = linkedHashMapO;
        new Handler(Looper.getMainLooper()).post(new com.facebook.login.E(perimeterXDelegate, linkedHashMapO, str, 10));
    }

    public final String r() {
        com.perimeterx.mobile_sdk.local_data.x xVar = com.perimeterx.mobile_sdk.local_data.x.b;
        String str = this.b.a;
        this.i.getClass();
        String strA = com.perimeterx.mobile_sdk.local_data.w.a(xVar, str);
        if (strA == null || strA.length() == 0) {
            return null;
        }
        return strA;
    }
}
