package androidx.work.impl.model;

import android.content.Context;
import android.database.Cursor;
import android.net.Uri;
import android.os.StatFs;
import android.util.SparseArray;
import android.view.ActionMode;
import android.view.Menu;
import android.view.MenuItem;
import androidx.appcompat.view.menu.C;
import androidx.collection.C0208f;
import androidx.collection.C0219q;
import androidx.collection.V;
import androidx.work.impl.WorkDatabase_Impl;
import com.google.android.gms.ads.internal.client.zze;
import com.google.android.gms.ads.internal.util.A;
import com.google.android.gms.internal.ads.AbstractC1795We;
import com.google.android.gms.internal.ads.AbstractC1972di;
import com.google.android.gms.internal.ads.AbstractC2773w7;
import com.google.android.gms.internal.ads.C1669Be;
import com.google.android.gms.internal.ads.C1778Tf;
import com.google.android.gms.internal.ads.C1789Ve;
import com.google.android.gms.internal.ads.C2668tp;
import com.google.android.gms.internal.ads.C2831xg;
import com.google.android.gms.internal.ads.Gh;
import com.google.android.gms.internal.ads.Pq;
import com.google.android.gms.internal.ads.Pv;
import com.google.android.gms.internal.ads.R7;
import com.google.android.gms.internal.ads.Rh;
import com.google.android.gms.internal.ads.SF;
import com.google.android.gms.internal.ads.Tq;
import com.google.android.gms.internal.ads.Uq;
import com.google.android.gms.internal.ads.Zg;
import com.google.android.gms.internal.mlkit_vision_camera.V1;
import com.google.android.gms.internal.mlkit_vision_camera.W1;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import kotlin.Pair;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class i implements Pv, SF {
    public final /* synthetic */ int a;
    public final Object b;
    public final Object c;
    public final Object d;
    public final Object e;

    public /* synthetic */ i(int i, String str, Object obj, Object obj2, Object obj3) {
        this.a = i;
        this.b = obj;
        this.c = str;
        this.d = obj2;
        this.e = obj3;
    }

    /* JADX WARN: Removed duplicated region for block: B:30:0x0055  */
    /* JADX WARN: Removed duplicated region for block: B:33:0x005e  */
    /* JADX WARN: Removed duplicated region for block: B:34:0x0069  */
    @Override // com.google.android.gms.internal.ads.SF
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public com.google.android.gms.internal.ads.Bu a(int r18, com.google.android.gms.internal.ads.J9 r19, int[] r20) {
        /*
            Method dump skipped, instructions count: 236
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.work.impl.model.i.a(int, com.google.android.gms.internal.ads.J9, int[]):com.google.android.gms.internal.ads.Bu");
    }

    public androidx.appcompat.view.f b(androidx.appcompat.view.b bVar) {
        ArrayList arrayList = (ArrayList) this.d;
        int size = arrayList.size();
        for (int i = 0; i < size; i++) {
            androidx.appcompat.view.f fVar = (androidx.appcompat.view.f) arrayList.get(i);
            if (fVar != null && fVar.b == bVar) {
                return fVar;
            }
        }
        androidx.appcompat.view.f fVar2 = new androidx.appcompat.view.f((Context) this.c, bVar);
        arrayList.add(fVar2);
        return fVar2;
    }

    @Override // com.google.android.gms.internal.ads.Pv
    /* renamed from: c */
    public void mo15c(Object obj) {
        Tq tq;
        switch (this.a) {
            case 3:
                ((C1669Be) this.e).v((Map) obj, (List) this.b, (String) this.c);
                return;
            default:
                C2668tp c2668tp = (C2668tp) this.e;
                C1778Tf c1778Tf = (C1778Tf) obj;
                synchronized (c2668tp) {
                    try {
                        if (c2668tp.m) {
                            c2668tp.c();
                        }
                        if (!((Boolean) R7.c.o()).booleanValue() || (tq = (Tq) this.b) == null) {
                            Uq uq = c2668tp.i;
                            Pq pq = (Pq) this.c;
                            pq.f(c1778Tf.a.b);
                            pq.I(c1778Tf.f.a);
                            pq.h(true);
                            uq.b(pq.l());
                        } else {
                            tq.g(c1778Tf.a.b);
                            tq.e(c1778Tf.f.a);
                            Pq pq2 = (Pq) this.c;
                            pq2.h(true);
                            tq.a(pq2);
                            tq.h();
                        }
                    } catch (Throwable th) {
                        throw th;
                    }
                }
                return;
        }
    }

    public g d(j id) {
        Intrinsics.checkNotNullParameter(id, "id");
        String str = id.a;
        androidx.room.u uVarA = androidx.room.u.a(2, "SELECT * FROM SystemIdInfo WHERE work_spec_id=? AND generation=?");
        uVarA.g(1, str);
        uVarA.z(2, id.b);
        WorkDatabase_Impl workDatabase_Impl = (WorkDatabase_Impl) this.b;
        workDatabase_Impl.b();
        Cursor cursorN = W1.N(workDatabase_Impl, uVarA, false);
        try {
            return cursorN.moveToFirst() ? new g(cursorN.getString(V1.H(cursorN, "work_spec_id")), cursorN.getInt(V1.H(cursorN, "generation")), cursorN.getInt(V1.H(cursorN, "system_id"))) : null;
        } finally {
            cursorN.close();
            uVarA.i();
        }
    }

    public void e(g gVar) {
        WorkDatabase_Impl workDatabase_Impl = (WorkDatabase_Impl) this.b;
        workDatabase_Impl.b();
        workDatabase_Impl.c();
        try {
            ((b) this.c).p(gVar);
            workDatabase_Impl.p();
        } finally {
            workDatabase_Impl.k();
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:30:0x00bb A[RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object f(com.quizlet.ads.c r11, kotlin.coroutines.jvm.internal.c r12) {
        /*
            r10 = this;
            boolean r0 = r12 instanceof com.quizlet.features.setpage.termlist.ads.b
            if (r0 == 0) goto L13
            r0 = r12
            com.quizlet.features.setpage.termlist.ads.b r0 = (com.quizlet.features.setpage.termlist.ads.b) r0
            int r1 = r0.p
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.p = r1
            goto L18
        L13:
            com.quizlet.features.setpage.termlist.ads.b r0 = new com.quizlet.features.setpage.termlist.ads.b
            r0.<init>(r10, r12)
        L18:
            java.lang.Object r12 = r0.n
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.p
            java.lang.String r3 = "await(...)"
            r4 = 3
            r5 = 2
            r6 = 1
            if (r2 == 0) goto L52
            if (r2 == r6) goto L45
            if (r2 == r5) goto L37
            if (r2 != r4) goto L2f
            androidx.glance.appwidget.protobuf.Z.e(r12)
            return r12
        L2f:
            java.lang.IllegalStateException r11 = new java.lang.IllegalStateException
            java.lang.String r12 = "call to 'resume' before 'invoke' with coroutine"
            r11.<init>(r12)
            throw r11
        L37:
            java.util.Map r11 = r0.m
            java.util.Map r11 = (java.util.Map) r11
            com.quizlet.ads.helper.b r2 = r0.l
            com.quizlet.ads.c r5 = r0.k
            androidx.work.impl.model.i r6 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r12)
            goto L96
        L45:
            com.quizlet.ads.helper.b r11 = r0.l
            com.quizlet.ads.c r2 = r0.k
            androidx.work.impl.model.i r6 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r12)
            r9 = r2
            r2 = r11
            r11 = r9
            goto L71
        L52:
            androidx.glance.appwidget.protobuf.Z.e(r12)
            java.lang.Object r12 = r10.b
            com.google.mlkit.vision.documentscanner.internal.c r12 = (com.google.mlkit.vision.documentscanner.internal.c) r12
            io.reactivex.rxjava3.internal.operators.flowable.b r12 = r12.g(r11)
            r0.j = r10
            r0.k = r11
            java.lang.Object r2 = r10.d
            com.quizlet.ads.helper.b r2 = (com.quizlet.ads.helper.b) r2
            r0.l = r2
            r0.p = r6
            java.lang.Object r12 = com.google.android.gms.internal.mlkit_vision_camera.I1.b(r12, r0)
            if (r12 != r1) goto L70
            goto Lba
        L70:
            r6 = r10
        L71:
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r12, r3)
            java.util.Map r12 = (java.util.Map) r12
            java.lang.Object r7 = r6.c
            com.quizlet.ads.b r7 = (com.quizlet.ads.b) r7
            io.reactivex.rxjava3.core.p r7 = r7.a()
            r0.j = r6
            r0.k = r11
            r0.l = r2
            r8 = r12
            java.util.Map r8 = (java.util.Map) r8
            r0.m = r8
            r0.p = r5
            java.lang.Object r5 = com.google.android.gms.internal.mlkit_vision_camera.I1.b(r7, r0)
            if (r5 != r1) goto L92
            goto Lba
        L92:
            r9 = r5
            r5 = r11
            r11 = r12
            r12 = r9
        L96:
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r12, r3)
            java.util.Map r12 = (java.util.Map) r12
            r2.getClass()
            com.google.android.gms.ads.admanager.AdManagerAdRequest r11 = com.quizlet.ads.helper.b.a(r11, r12)
            com.quizlet.features.setpage.termlist.ads.d r12 = new com.quizlet.features.setpage.termlist.ads.d
            r2 = 0
            r12.<init>(r6, r5, r11, r2)
            r0.j = r2
            r0.k = r2
            r0.l = r2
            r0.m = r2
            r0.p = r4
            r2 = 10000(0x2710, double:4.9407E-320)
            java.lang.Object r11 = kotlinx.coroutines.E.L(r2, r12, r0)
            if (r11 != r1) goto Lbb
        Lba:
            return r1
        Lbb:
            return r11
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.work.impl.model.i.f(com.quizlet.ads.c, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:17:0x004d  */
    /* JADX WARN: Removed duplicated region for block: B:22:0x0073  */
    /* JADX WARN: Removed duplicated region for block: B:23:0x0077 A[RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:18:0x006c -> B:20:0x006f). Please report as a decompilation issue!!! */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object g(kotlin.coroutines.jvm.internal.c r8) {
        /*
            r7 = this;
            boolean r0 = r8 instanceof com.quizlet.features.setpage.termlist.ads.e
            if (r0 == 0) goto L13
            r0 = r8
            com.quizlet.features.setpage.termlist.ads.e r0 = (com.quizlet.features.setpage.termlist.ads.e) r0
            int r1 = r0.o
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.o = r1
            goto L18
        L13:
            com.quizlet.features.setpage.termlist.ads.e r0 = new com.quizlet.features.setpage.termlist.ads.e
            r0.<init>(r7, r8)
        L18:
            java.lang.Object r8 = r0.m
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.o
            r3 = 1
            if (r2 == 0) goto L35
            if (r2 != r3) goto L2d
            java.util.Iterator r2 = r0.l
            java.util.List r4 = r0.k
            androidx.work.impl.model.i r5 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L6f
        L2d:
            java.lang.IllegalStateException r8 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r8.<init>(r0)
            throw r8
        L35:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            java.util.ArrayList r8 = new java.util.ArrayList
            r8.<init>()
            java.lang.Object r2 = r7.e
            java.util.List r2 = (java.util.List) r2
            java.util.Iterator r2 = r2.iterator()
            r5 = r7
            r4 = r8
        L47:
            boolean r8 = r2.hasNext()
            if (r8 == 0) goto L77
            java.lang.Object r8 = r2.next()
            java.lang.Number r8 = (java.lang.Number) r8
            int r8 = r8.intValue()
            com.google.mlkit.common.sdkinternal.model.a r6 = com.quizlet.ads.c.b
            r6.getClass()
            com.quizlet.ads.c r8 = com.google.mlkit.common.sdkinternal.model.a.r(r8)
            r0.j = r5
            r0.k = r4
            r0.l = r2
            r0.o = r3
            java.lang.Object r8 = r5.f(r8, r0)
            if (r8 != r1) goto L6f
            return r1
        L6f:
            com.quizlet.features.setpage.termlist.ads.a r8 = (com.quizlet.features.setpage.termlist.ads.a) r8
            if (r8 == 0) goto L47
            r4.add(r8)
            goto L47
        L77:
            return r4
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.work.impl.model.i.g(kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public boolean h(androidx.appcompat.view.b bVar, MenuItem menuItem) {
        return ((ActionMode.Callback) this.b).onActionItemClicked(b(bVar), new androidx.appcompat.view.menu.u((Context) this.c, (androidx.core.internal.view.a) menuItem));
    }

    public boolean i(androidx.appcompat.view.b bVar, androidx.appcompat.view.menu.n nVar) {
        androidx.appcompat.view.f fVarB = b(bVar);
        V v = (V) this.e;
        Menu c = (Menu) v.get(nVar);
        if (c == null) {
            c = new C((Context) this.c, nVar);
            v.put(nVar, c);
        }
        return ((ActionMode.Callback) this.b).onCreateActionMode(fVarB, c);
    }

    @Override // com.google.android.gms.internal.ads.Pv
    public void zza(Throwable th) {
        Tq tq;
        int i;
        switch (this.a) {
            case 3:
                com.google.android.gms.ads.internal.util.client.i.h("Failed to parse gmsg params for: ".concat(String.valueOf((Uri) this.d)));
                return;
            default:
                if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.L5)).booleanValue()) {
                    A.m();
                }
                C2668tp c2668tp = (C2668tp) this.e;
                synchronized (c2668tp) {
                    C1789Ve c1789Ve = (C1789Ve) this.d;
                    zze zzeVarL = AbstractC1972di.l(th, ((C2831xg) c1789Ve.t0.zzb()).l);
                    c2668tp.n = zzeVarL;
                    ((Zg) c1789Ve.j0.zzb()).m0(zzeVarL);
                    AbstractC1795We.n(zzeVarL.a, "BannerAdLoader.onFailure", th);
                    if (c2668tp.m) {
                        c2668tp.e();
                        Gh gh = c2668tp.h;
                        Rh rh = c2668tp.j;
                        synchronized (rh) {
                            i = rh.a;
                        }
                        gh.k1(i);
                    }
                    if (!((Boolean) R7.c.o()).booleanValue() || (tq = (Tq) this.b) == null) {
                        Uq uq = c2668tp.i;
                        Pq pq = (Pq) this.c;
                        pq.j(zzeVarL);
                        pq.g(th);
                        pq.h(false);
                        uq.b(pq.l());
                    } else {
                        tq.c(zzeVarL);
                        Pq pq2 = (Pq) this.c;
                        pq2.g(th);
                        pq2.h(false);
                        tq.a(pq2);
                        tq.h();
                    }
                }
                return;
        }
    }

    public /* synthetic */ i(Object obj, Object obj2, Object obj3, Object obj4, int i) {
        this.a = i;
        this.b = obj2;
        this.c = obj3;
        this.d = obj4;
        this.e = obj;
    }

    public i(com.google.mlkit.vision.documentscanner.internal.c adBidTargetsProvider, com.quizlet.ads.b adTargetsManager, com.quizlet.ads.helper.b adLoaderHelper, List nativeAdIdList) {
        this.a = 7;
        Intrinsics.checkNotNullParameter(adBidTargetsProvider, "adBidTargetsProvider");
        Intrinsics.checkNotNullParameter(adTargetsManager, "adTargetsManager");
        Intrinsics.checkNotNullParameter(adLoaderHelper, "adLoaderHelper");
        Intrinsics.checkNotNullParameter(nativeAdIdList, "nativeAdIdList");
        this.b = adBidTargetsProvider;
        this.c = adTargetsManager;
        this.d = adLoaderHelper;
        this.e = nativeAdIdList;
    }

    public i() {
        this.a = 2;
        this.b = new C0208f(0);
        this.c = new SparseArray();
        this.d = new C0219q((Object) null);
        this.e = new C0208f(0);
    }

    public i(Context context, StatFs deviceStorageInformationStatFs) {
        this.a = 8;
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(deviceStorageInformationStatFs, "deviceStorageInformationStatFs");
        this.b = context;
        this.c = deviceStorageInformationStatFs;
        this.d = kotlin.collections.V.f(new Pair(3221225472L, 10485760L), new Pair(6442450944L, 29360128L), new Pair(Long.MAX_VALUE, 52428800L));
        this.e = kotlin.collections.V.f(new Pair(68719476736L, 52428800L), new Pair(274877906944L, 104857600L), new Pair(Long.MAX_VALUE, 209715200L));
    }

    public i(WorkDatabase_Impl database) {
        this.a = 0;
        this.b = database;
        Intrinsics.checkNotNullParameter(database, "database");
        this.c = new b(database, 2);
        this.d = new h(database, 0);
        this.e = new h(database, 1);
    }

    public i(Context context, ActionMode.Callback callback) {
        this.a = 1;
        this.c = context;
        this.b = callback;
        this.d = new ArrayList();
        this.e = new V(0);
    }
}
