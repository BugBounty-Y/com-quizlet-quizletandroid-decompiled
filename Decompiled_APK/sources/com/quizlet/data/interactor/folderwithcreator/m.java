package com.quizlet.data.interactor.folderwithcreator;

import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.text.SpannableStringBuilder;
import android.util.Base64;
import android.util.Pair;
import android.util.Range;
import android.util.Size;
import android.view.View;
import androidx.camera.core.C0196t;
import androidx.camera.core.impl.C0168g;
import androidx.constraintlayout.widget.o;
import com.google.android.datatransport.cct.internal.s;
import com.google.android.gms.ads.internal.client.r;
import com.google.android.gms.ads.internal.client.zze;
import com.google.android.gms.ads.internal.util.A;
import com.google.android.gms.internal.ads.AbstractC1795We;
import com.google.android.gms.internal.ads.AbstractC1972di;
import com.google.android.gms.internal.ads.AbstractC1981ds;
import com.google.android.gms.internal.ads.AbstractC2773w7;
import com.google.android.gms.internal.ads.C1765Re;
import com.google.android.gms.internal.ads.C1813Ze;
import com.google.android.gms.internal.ads.C1882bf;
import com.google.android.gms.internal.ads.C2147hi;
import com.google.android.gms.internal.ads.C2511q2;
import com.google.android.gms.internal.ads.C2596s2;
import com.google.android.gms.internal.ads.C2601s7;
import com.google.android.gms.internal.ads.C2682u2;
import com.google.android.gms.internal.ads.C2747vi;
import com.google.android.gms.internal.ads.C2754vp;
import com.google.android.gms.internal.ads.C2788wg;
import com.google.android.gms.internal.ads.C2831xg;
import com.google.android.gms.internal.ads.C2881yn;
import com.google.android.gms.internal.ads.Gg;
import com.google.android.gms.internal.ads.Gp;
import com.google.android.gms.internal.ads.Kp;
import com.google.android.gms.internal.ads.Lh;
import com.google.android.gms.internal.ads.Ln;
import com.google.android.gms.internal.ads.Pg;
import com.google.android.gms.internal.ads.Pq;
import com.google.android.gms.internal.ads.Pv;
import com.google.android.gms.internal.ads.R7;
import com.google.android.gms.internal.ads.Rn;
import com.google.android.gms.internal.ads.Sg;
import com.google.android.gms.internal.ads.Tq;
import com.google.android.gms.internal.ads.Ts;
import com.google.android.gms.internal.ads.Uq;
import com.google.android.gms.internal.ads.Y1;
import com.google.android.gms.internal.ads.Zg;
import com.google.android.gms.internal.ads.Zh;
import com.quizlet.assembly.compose.modals.x;
import com.quizlet.db.data.models.persisted.DBTerm;
import com.skydoves.balloon.internals.DefinitionKt;
import io.reactivex.rxjava3.core.p;
import io.reactivex.rxjava3.internal.operators.observable.o0;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.TreeSet;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class m implements Y1, Pg, Pv, io.reactivex.rxjava3.functions.h {
    public Object a;
    public Object b;
    public Object c;
    public Object d;
    public Object e;

    public /* synthetic */ m(Object obj, Object obj2, Object obj3, Object obj4, Object obj5) {
        this.a = obj;
        this.b = obj2;
        this.c = obj3;
        this.d = obj4;
        this.e = obj5;
    }

    public static androidx.constraintlayout.core.widgets.e k(androidx.constraintlayout.core.widgets.f fVar, View view) {
        if (fVar.i0 == view) {
            return fVar;
        }
        ArrayList arrayList = fVar.t0;
        int size = arrayList.size();
        for (int i = 0; i < size; i++) {
            androidx.constraintlayout.core.widgets.e eVar = (androidx.constraintlayout.core.widgets.e) arrayList.get(i);
            if (eVar.i0 == view) {
                return eVar;
            }
        }
        return null;
    }

    @Override // com.google.android.gms.internal.ads.Y1
    public long F(int i) {
        return ((long[]) this.b)[i];
    }

    @Override // com.google.android.gms.internal.ads.Pg
    public /* synthetic */ Pg a(C2754vp c2754vp) {
        this.c = c2754vp;
        return this;
    }

    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        String str;
        Unit file = (Unit) obj;
        Intrinsics.checkNotNullParameter(file, "file");
        if (!((DBTerm) this.a).hasDefinitionImage()) {
            return io.reactivex.rxjava3.core.g.c(file);
        }
        String str2 = (String) this.b;
        if (str2 == null || (str = (String) this.c) == null) {
            return io.reactivex.rxjava3.internal.operators.maybe.f.a;
        }
        s sVar = (s) this.d;
        com.quizlet.qutils.data.offline.b bVar = com.quizlet.qutils.data.offline.b.c;
        com.quizlet.qutils.data.offline.d dVar = (com.quizlet.qutils.data.offline.d) this.e;
        return new io.reactivex.rxjava3.internal.operators.maybe.j(((com.quizlet.quizletandroid.ui.common.images.loading.offline.c) sVar.c).a(dVar.a(str2, bVar)), new com.quizlet.data.repository.folderwithcreator.e(sVar, dVar, str, 14), 0);
    }

    @Override // com.google.android.gms.internal.ads.Pg
    public /* synthetic */ Pg b(Gp gp) {
        this.b = gp;
        return this;
    }

    @Override // com.google.android.gms.internal.ads.Pv
    /* renamed from: c */
    public void mo15c(Object obj) {
        Tq tq;
        C2747vi c2747vi = (C2747vi) obj;
        Kp kp = (Kp) this.e;
        synchronized (kp) {
            try {
                kp.i = null;
                C2601s7 c2601s7 = AbstractC2773w7.i8;
                r rVar = r.d;
                if (((Boolean) rVar.c.a(c2601s7)).booleanValue()) {
                    C2881yn c2881yn = c2747vi.g.a;
                    Ln ln = kp.d;
                    Lh lh = (Lh) c2881yn.b;
                    lh.b = ln;
                    lh.e = kp.e;
                }
                ((Rn) this.a).o(c2747vi);
                if (((Boolean) rVar.c.a(c2601s7)).booleanValue()) {
                    final int i = 0;
                    kp.b.execute(new Runnable(this) { // from class: com.google.android.gms.internal.ads.Jp
                        public final /* synthetic */ com.quizlet.data.interactor.folderwithcreator.m b;

                        {
                            this.b = this;
                        }

                        @Override // java.lang.Runnable
                        public final void run() {
                            switch (i) {
                                case 0:
                                    ((Kp) this.b.e).d.s();
                                    break;
                                default:
                                    ((Kp) this.b.e).e.s();
                                    break;
                            }
                        }
                    });
                    final int i2 = 1;
                    kp.b.execute(new Runnable(this) { // from class: com.google.android.gms.internal.ads.Jp
                        public final /* synthetic */ com.quizlet.data.interactor.folderwithcreator.m b;

                        {
                            this.b = this;
                        }

                        @Override // java.lang.Runnable
                        public final void run() {
                            switch (i2) {
                                case 0:
                                    ((Kp) this.b.e).d.s();
                                    break;
                                default:
                                    ((Kp) this.b.e).e.s();
                                    break;
                            }
                        }
                    });
                }
                if (!((Boolean) R7.c.o()).booleanValue() || (tq = (Tq) this.b) == null) {
                    Uq uq = kp.g;
                    Pq pq = (Pq) this.c;
                    pq.f(c2747vi.a.b);
                    pq.I(c2747vi.f.a);
                    pq.h(true);
                    uq.b(pq.l());
                } else {
                    tq.g(c2747vi.a.b);
                    tq.e(c2747vi.f.a);
                    Pq pq2 = (Pq) this.c;
                    pq2.h(true);
                    tq.a(pq2);
                    tq.h();
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public C0168g d() {
        String strK = ((Size) this.a) == null ? " resolution" : "";
        if (((C0196t) this.b) == null) {
            strK = strK.concat(" dynamicRange");
        }
        if (((Range) this.c) == null) {
            strK = android.support.v4.media.session.a.k(strK, " expectedFrameRateRange");
        }
        if (((Boolean) this.e) == null) {
            strK = android.support.v4.media.session.a.k(strK, " zslDisabled");
        }
        if (strK.isEmpty()) {
            return new C0168g((Size) this.a, (C0196t) this.b, (Range) this.c, (androidx.camera.camera2.impl.b) this.d, ((Boolean) this.e).booleanValue());
        }
        throw new IllegalStateException("Missing required properties:".concat(strK));
    }

    public void e(int i, int i2) {
        androidx.constraintlayout.motion.widget.r rVar = (androidx.constraintlayout.motion.widget.r) this.e;
        int optimizationLevel = rVar.getOptimizationLevel();
        if (rVar.u == rVar.getStartState()) {
            androidx.constraintlayout.core.widgets.f fVar = (androidx.constraintlayout.core.widgets.f) this.b;
            o oVar = (o) this.d;
            rVar.n(fVar, optimizationLevel, (oVar == null || oVar.a == 0) ? i : i2, (oVar == null || oVar.a == 0) ? i2 : i);
            o oVar2 = (o) this.c;
            if (oVar2 != null) {
                androidx.constraintlayout.core.widgets.f fVar2 = (androidx.constraintlayout.core.widgets.f) this.a;
                int i3 = oVar2.a;
                int i4 = i3 == 0 ? i : i2;
                if (i3 == 0) {
                    i = i2;
                }
                rVar.n(fVar2, optimizationLevel, i4, i);
                return;
            }
            return;
        }
        o oVar3 = (o) this.c;
        if (oVar3 != null) {
            androidx.constraintlayout.core.widgets.f fVar3 = (androidx.constraintlayout.core.widgets.f) this.a;
            int i5 = oVar3.a;
            rVar.n(fVar3, optimizationLevel, i5 == 0 ? i : i2, i5 == 0 ? i2 : i);
        }
        androidx.constraintlayout.core.widgets.f fVar4 = (androidx.constraintlayout.core.widgets.f) this.b;
        o oVar4 = (o) this.d;
        int i6 = (oVar4 == null || oVar4.a == 0) ? i : i2;
        if (oVar4 == null || oVar4.a == 0) {
            i = i2;
        }
        rVar.n(fVar4, optimizationLevel, i6, i);
    }

    /* JADX WARN: Removed duplicated region for block: B:26:0x004e A[Catch: Exception -> 0x0029, TryCatch #0 {Exception -> 0x0029, blocks: (B:12:0x0025, B:24:0x0046, B:26:0x004e, B:28:0x0053), top: B:40:0x0025 }] */
    /* JADX WARN: Removed duplicated region for block: B:28:0x0053 A[Catch: Exception -> 0x0029, TRY_LEAVE, TryCatch #0 {Exception -> 0x0029, blocks: (B:12:0x0025, B:24:0x0046, B:26:0x004e, B:28:0x0053), top: B:40:0x0025 }] */
    /* JADX WARN: Removed duplicated region for block: B:37:0x006d  */
    /* JADX WARN: Removed duplicated region for block: B:38:0x007a  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object f(long r5, kotlin.coroutines.jvm.internal.c r7) throws java.lang.Throwable {
        /*
            r4 = this;
            boolean r0 = r7 instanceof com.quizlet.features.folders.viewmodel.usecases.n
            if (r0 == 0) goto L13
            r0 = r7
            com.quizlet.features.folders.viewmodel.usecases.n r0 = (com.quizlet.features.folders.viewmodel.usecases.n) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.quizlet.features.folders.viewmodel.usecases.n r0 = new com.quizlet.features.folders.viewmodel.usecases.n
            r0.<init>(r4, r7)
        L18:
            java.lang.Object r7 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            if (r2 == 0) goto L33
            if (r2 != r3) goto L2b
            com.quizlet.data.interactor.folderwithcreator.m r5 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r7)     // Catch: java.lang.Exception -> L29
            goto L46
        L29:
            r6 = move-exception
            goto L69
        L2b:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L33:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            java.lang.Object r7 = r4.a     // Catch: java.lang.Exception -> L66
            androidx.work.impl.model.c r7 = (androidx.work.impl.model.c) r7     // Catch: java.lang.Exception -> L66
            r0.j = r4     // Catch: java.lang.Exception -> L64
            r0.m = r3     // Catch: java.lang.Exception -> L64
            java.lang.Object r7 = r7.p(r5, r0)     // Catch: java.lang.Exception -> L64
            if (r7 != r1) goto L45
            return r1
        L45:
            r5 = r4
        L46:
            com.quizlet.data.model.d0 r7 = (com.quizlet.data.model.AbstractC4119d0) r7     // Catch: java.lang.Exception -> L29
            boolean r6 = r7.d()     // Catch: java.lang.Exception -> L29
            if (r6 == 0) goto L53
            kotlin.p r6 = kotlin.r.b     // Catch: java.lang.Exception -> L29
            kotlin.Unit r5 = kotlin.Unit.a     // Catch: java.lang.Exception -> L29
            return r5
        L53:
            r5.getClass()     // Catch: java.lang.Exception -> L29
            kotlin.p r6 = kotlin.r.b     // Catch: java.lang.Exception -> L29
            com.quizlet.features.folders.viewmodel.usecases.DeleteFolderException r6 = new com.quizlet.features.folders.viewmodel.usecases.DeleteFolderException     // Catch: java.lang.Exception -> L29
            r6.<init>()     // Catch: java.lang.Exception -> L29
            kotlin.q r5 = androidx.glance.appwidget.protobuf.Z.b(r6)     // Catch: java.lang.Exception -> L29
            return r5
        L62:
            r5 = r4
            goto L69
        L64:
            r6 = move-exception
            goto L62
        L66:
            r5 = move-exception
            r6 = r5
            goto L62
        L69:
            boolean r6 = r6 instanceof java.net.UnknownHostException
            if (r6 == 0) goto L7a
            kotlin.p r5 = kotlin.r.b
            com.quizlet.data.connectivity.NetworkOfflineError r5 = new com.quizlet.data.connectivity.NetworkOfflineError
            r6 = 0
            r5.<init>(r6)
            kotlin.q r5 = androidx.glance.appwidget.protobuf.Z.b(r5)
            goto L88
        L7a:
            r5.getClass()
            kotlin.p r5 = kotlin.r.b
            com.quizlet.features.folders.viewmodel.usecases.DeleteFolderException r5 = new com.quizlet.features.folders.viewmodel.usecases.DeleteFolderException
            r5.<init>()
            kotlin.q r5 = androidx.glance.appwidget.protobuf.Z.b(r5)
        L88:
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.interactor.folderwithcreator.m.f(long, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object h(long r6, kotlin.coroutines.jvm.internal.c r8) throws java.lang.Throwable {
        /*
            r5 = this;
            boolean r0 = r8 instanceof com.quizlet.data.interactor.folderwithcreator.a
            if (r0 == 0) goto L13
            r0 = r8
            com.quizlet.data.interactor.folderwithcreator.a r0 = (com.quizlet.data.interactor.folderwithcreator.a) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.data.interactor.folderwithcreator.a r0 = new com.quizlet.data.interactor.folderwithcreator.a
            r0.<init>(r5, r8)
        L18:
            java.lang.Object r8 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L31
            if (r2 != r3) goto L29
            androidx.glance.appwidget.protobuf.Z.e(r8)     // Catch: java.lang.Exception -> L27
            goto L47
        L27:
            r6 = move-exception
            goto L4a
        L29:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r7 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r7)
            throw r6
        L31:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            java.lang.Object r8 = r5.c     // Catch: java.lang.Exception -> L27
            kotlinx.coroutines.y r8 = (kotlinx.coroutines.AbstractC5040y) r8     // Catch: java.lang.Exception -> L27
            com.quizlet.data.interactor.folderwithcreator.f r2 = new com.quizlet.data.interactor.folderwithcreator.f     // Catch: java.lang.Exception -> L27
            r4 = 0
            r2.<init>(r5, r6, r4)     // Catch: java.lang.Exception -> L27
            r0.l = r3     // Catch: java.lang.Exception -> L27
            java.lang.Object r8 = kotlinx.coroutines.E.J(r8, r2, r0)     // Catch: java.lang.Exception -> L27
            if (r8 != r1) goto L47
            return r1
        L47:
            kotlinx.coroutines.flow.i r8 = (kotlinx.coroutines.flow.InterfaceC4992i) r8     // Catch: java.lang.Exception -> L27
            return r8
        L4a:
            com.quizlet.data.exceptions.library.LibraryFoldersException r7 = new com.quizlet.data.exceptions.library.LibraryFoldersException
            r7.<init>(r6)
            throw r7
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.interactor.folderwithcreator.m.h(long, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public o0 i(List creatorIds, p stopToken) {
        Intrinsics.checkNotNullParameter(creatorIds, "creatorIds");
        Intrinsics.checkNotNullParameter(stopToken, "stopToken");
        return ((androidx.work.impl.model.c) this.b).b(stopToken, new com.braze.triggers.managers.h(25, this, creatorIds));
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object j(long r5, kotlin.coroutines.jvm.internal.c r7) throws java.lang.Throwable {
        /*
            r4 = this;
            boolean r0 = r7 instanceof com.quizlet.data.interactor.folderwithcreator.j
            if (r0 == 0) goto L13
            r0 = r7
            com.quizlet.data.interactor.folderwithcreator.j r0 = (com.quizlet.data.interactor.folderwithcreator.j) r0
            int r1 = r0.n
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.n = r1
            goto L18
        L13:
            com.quizlet.data.interactor.folderwithcreator.j r0 = new com.quizlet.data.interactor.folderwithcreator.j
            r0.<init>(r4, r7)
        L18:
            java.lang.Object r7 = r0.l
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.n
            r3 = 1
            if (r2 == 0) goto L33
            if (r2 != r3) goto L2b
            long r5 = r0.k
            com.quizlet.data.interactor.folderwithcreator.m r0 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L44
        L2b:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L33:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            r0.j = r4
            r0.k = r5
            r0.n = r3
            java.lang.Object r7 = r4.h(r5, r0)
            if (r7 != r1) goto L43
            return r1
        L43:
            r0 = r4
        L44:
            kotlinx.coroutines.flow.i r7 = (kotlinx.coroutines.flow.InterfaceC4992i) r7
            com.quizlet.data.interactor.folderwithcreator.l r1 = new com.quizlet.data.interactor.folderwithcreator.l
            r2 = 0
            r1.<init>(r0, r5, r2)
            androidx.paging.J0 r3 = new androidx.paging.J0
            r3.<init>(r7, r1)
            r0.getClass()
            java.lang.Object r7 = r0.a     // Catch: java.lang.Exception -> L9a
            com.quizlet.data.repository.folderwithcreator.e r7 = (com.quizlet.data.repository.folderwithcreator.e) r7     // Catch: java.lang.Exception -> L9a
            java.lang.Long r5 = java.lang.Long.valueOf(r5)     // Catch: java.lang.Exception -> L9a
            java.util.List r5 = kotlin.collections.A.b(r5)     // Catch: java.lang.Exception -> L9a
            io.reactivex.rxjava3.internal.operators.observable.J r5 = r7.h(r5)     // Catch: java.lang.Exception -> L9a
            kotlinx.coroutines.flow.c r5 = com.google.android.gms.internal.mlkit_vision_camera.K1.f(r5)     // Catch: java.lang.Exception -> L9a
            kotlinx.coroutines.flow.i r5 = kotlinx.coroutines.flow.e0.m(r5)     // Catch: java.lang.Exception -> L9a
            com.quizlet.data.interactor.folderwithcreator.h r6 = new com.quizlet.data.interactor.folderwithcreator.h     // Catch: java.lang.Exception -> L9a
            r6.<init>(r5, r2)     // Catch: java.lang.Exception -> L9a
            androidx.datastore.core.t r5 = new androidx.datastore.core.t     // Catch: java.lang.Exception -> L9a
            r5.<init>(r6)     // Catch: java.lang.Exception -> L9a
            com.quizlet.data.interactor.folderwithcreator.b r6 = new com.quizlet.data.interactor.folderwithcreator.b     // Catch: java.lang.Exception -> L9a
            r7 = 3
            r1 = 1
            r6.<init>(r7, r1, r2)     // Catch: java.lang.Exception -> L9a
            androidx.paging.J0 r1 = new androidx.paging.J0     // Catch: java.lang.Exception -> L9a
            r1.<init>(r5, r6)     // Catch: java.lang.Exception -> L9a
            java.lang.Object r5 = r0.c     // Catch: java.lang.Exception -> L9a
            kotlinx.coroutines.y r5 = (kotlinx.coroutines.AbstractC5040y) r5     // Catch: java.lang.Exception -> L9a
            kotlinx.coroutines.flow.i r5 = kotlinx.coroutines.flow.e0.s(r1, r5)     // Catch: java.lang.Exception -> L9a
            com.quizlet.data.interactor.folderwithcreator.k r6 = new com.quizlet.data.interactor.folderwithcreator.k
            r6.<init>(r7, r2)
            com.quizlet.features.folders.addtofolder.viewmodel.usecase.c r7 = new com.quizlet.features.folders.addtofolder.viewmodel.usecase.c
            r0 = 2
            r7.<init>(r5, r3, r6, r0)
            kotlinx.coroutines.flow.i r5 = kotlinx.coroutines.flow.e0.m(r7)
            return r5
        L9a:
            r5 = move-exception
            com.quizlet.data.exceptions.library.LibraryFoldersException r6 = new com.quizlet.data.exceptions.library.LibraryFoldersException
            r6.<init>(r5)
            throw r6
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.interactor.folderwithcreator.m.j(long, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Code restructure failed: missing block: B:26:0x0062, code lost:
    
        if (r12 == r1) goto L35;
     */
    /* JADX WARN: Code restructure failed: missing block: B:34:0x007d, code lost:
    
        if (r12 == r1) goto L35;
     */
    /* JADX WARN: Code restructure failed: missing block: B:35:0x007f, code lost:
    
        return r1;
     */
    /* JADX WARN: Removed duplicated region for block: B:8:0x0016  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object l(com.quizlet.data.interactor.folderwithcreator.m r12, long r13, long r15, long r17, boolean r19, boolean r20, kotlin.coroutines.jvm.internal.c r21) throws java.lang.Throwable {
        /*
            r11 = this;
            r0 = r21
            boolean r1 = r0 instanceof com.quizlet.features.folders.viewmodel.usecases.o
            if (r1 == 0) goto L16
            r1 = r0
            com.quizlet.features.folders.viewmodel.usecases.o r1 = (com.quizlet.features.folders.viewmodel.usecases.o) r1
            int r2 = r1.l
            r3 = -2147483648(0xffffffff80000000, float:-0.0)
            r4 = r2 & r3
            if (r4 == 0) goto L16
            int r2 = r2 - r3
            r1.l = r2
        L14:
            r10 = r1
            goto L1c
        L16:
            com.quizlet.features.folders.viewmodel.usecases.o r1 = new com.quizlet.features.folders.viewmodel.usecases.o
            r1.<init>(r11, r0)
            goto L14
        L1c:
            java.lang.Object r0 = r10.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r10.l
            r3 = 2
            r4 = 1
            if (r2 == 0) goto L40
            if (r2 == r4) goto L38
            if (r2 != r3) goto L30
            androidx.glance.appwidget.protobuf.Z.e(r0)
            kotlin.r r0 = (kotlin.r) r0
            goto L3d
        L30:
            java.lang.IllegalStateException r12 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r12.<init>(r0)
            throw r12
        L38:
            androidx.glance.appwidget.protobuf.Z.e(r0)
            kotlin.r r0 = (kotlin.r) r0
        L3d:
            java.lang.Object r12 = r0.a
            goto L65
        L40:
            androidx.glance.appwidget.protobuf.Z.e(r0)
            r0 = 0
            if (r19 != 0) goto L47
            return r0
        L47:
            r5 = 0
            int r2 = (r13 > r5 ? 1 : (r13 == r5 ? 0 : -1))
            if (r2 <= 0) goto L67
            int r2 = (r15 > r5 ? 1 : (r15 == r5 ? 0 : -1))
            if (r2 <= 0) goto L67
            java.lang.Object r12 = r12.c
            r2 = r12
            com.quizlet.data.interactor.folder.c r2 = (com.quizlet.data.interactor.folder.c) r2
            r10.l = r4
            r5 = r13
            r7 = r15
            r3 = r17
            r9 = r20
            java.lang.Object r12 = r2.b(r3, r5, r7, r9, r10)
            if (r12 != r1) goto L65
            goto L7f
        L65:
            r0 = r12
            goto L82
        L67:
            r4 = -1
            int r2 = (r13 > r4 ? 1 : (r13 == r4 ? 0 : -1))
            if (r2 != 0) goto L80
            int r2 = (r15 > r4 ? 1 : (r15 == r4 ? 0 : -1))
            if (r2 != 0) goto L80
            java.lang.Object r12 = r12.d
            com.quizlet.data.repository.explanations.myexplanations.a r12 = (com.quizlet.data.repository.explanations.myexplanations.a) r12
            r10.l = r3
            r3 = r17
            java.lang.Object r12 = r12.h(r3, r10)
            if (r12 != r1) goto L65
        L7f:
            return r1
        L80:
            kotlin.p r12 = kotlin.r.b
        L82:
            androidx.glance.appwidget.protobuf.Z.e(r0)
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.interactor.folderwithcreator.m.l(com.quizlet.data.interactor.folderwithcreator.m, long, long, long, boolean, boolean, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public void m() {
        int iOrdinal = ((com.quizlet.features.settings.data.models.f) this.a).ordinal();
        if (iOrdinal == 0) {
            x.d((x) this.d);
        } else if (iOrdinal == 1) {
            x.d((x) this.c);
        } else {
            if (iOrdinal != 2) {
                throw new NoWhenBranchMatchedException();
            }
            x.d((x) this.e);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:41:0x00c1  */
    /* JADX WARN: Removed duplicated region for block: B:45:0x00dd  */
    /* JADX WARN: Removed duplicated region for block: B:72:0x0136  */
    /* JADX WARN: Removed duplicated region for block: B:73:0x0143  */
    /* JADX WARN: Removed duplicated region for block: B:8:0x0018  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object n(long r20, java.lang.String r22, long r23, long r25, boolean r27, kotlin.coroutines.jvm.internal.c r28) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 349
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.interactor.folderwithcreator.m.n(long, java.lang.String, long, long, boolean, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    @Override // com.google.android.gms.internal.ads.Pg
    /* renamed from: o, reason: merged with bridge method [inline-methods] */
    public C1882bf g() {
        AbstractC1981ds.w(Zh.class, (Zh) this.d);
        AbstractC1981ds.w(Sg.class, (Sg) this.e);
        return new C1882bf((C1765Re) this.a, new C2147hi(13, (byte) 0), (Zh) this.d, (Sg) this.e, new Ts(), (Gp) this.b, (C2754vp) this.c);
    }

    @Override // com.google.android.gms.internal.ads.Y1
    public int zza() {
        return ((long[]) this.b).length;
    }

    @Override // com.google.android.gms.internal.ads.Y1
    public ArrayList zzc(long j) {
        C2596s2 c2596s2 = (C2596s2) this.a;
        ArrayList arrayList = new ArrayList();
        String str = c2596s2.h;
        c2596s2.h(j, str, arrayList);
        TreeMap treeMap = new TreeMap();
        c2596s2.j(j, false, str, treeMap);
        HashMap map = (HashMap) this.d;
        c2596s2.i(j, (Map) this.c, map, str, treeMap);
        ArrayList arrayList2 = new ArrayList();
        int size = arrayList.size();
        for (int i = 0; i < size; i++) {
            Pair pair = (Pair) arrayList.get(i);
            String str2 = (String) ((HashMap) this.e).get(pair.second);
            if (str2 != null) {
                byte[] bArrDecode = Base64.decode(str2, 0);
                Bitmap bitmapDecodeByteArray = BitmapFactory.decodeByteArray(bArrDecode, 0, bArrDecode.length);
                C2682u2 c2682u2 = (C2682u2) map.get(pair.first);
                c2682u2.getClass();
                arrayList2.add(new Gg(null, null, null, bitmapDecodeByteArray, c2682u2.c, 0, c2682u2.e, c2682u2.b, 0, Integer.MIN_VALUE, -3.4028235E38f, c2682u2.f, c2682u2.g, c2682u2.j, DefinitionKt.NO_Float_VALUE));
            }
        }
        for (Map.Entry entry : treeMap.entrySet()) {
            C2682u2 c2682u22 = (C2682u2) map.get(entry.getKey());
            c2682u22.getClass();
            C2788wg c2788wg = (C2788wg) entry.getValue();
            CharSequence charSequence = c2788wg.a;
            charSequence.getClass();
            SpannableStringBuilder spannableStringBuilder = (SpannableStringBuilder) charSequence;
            for (C2511q2 c2511q2 : (C2511q2[]) spannableStringBuilder.getSpans(0, spannableStringBuilder.length(), C2511q2.class)) {
                spannableStringBuilder.replace(spannableStringBuilder.getSpanStart(c2511q2), spannableStringBuilder.getSpanEnd(c2511q2), (CharSequence) "");
            }
            int i2 = 0;
            while (i2 < spannableStringBuilder.length()) {
                int i3 = i2 + 1;
                if (spannableStringBuilder.charAt(i2) == ' ') {
                    int i4 = i3;
                    while (i4 < spannableStringBuilder.length() && spannableStringBuilder.charAt(i4) == ' ') {
                        i4++;
                    }
                    int i5 = i4 - i3;
                    if (i5 > 0) {
                        spannableStringBuilder.delete(i2, i5 + i2);
                    }
                }
                i2 = i3;
            }
            if (spannableStringBuilder.length() > 0 && spannableStringBuilder.charAt(0) == ' ') {
                spannableStringBuilder.delete(0, 1);
            }
            int i6 = 0;
            while (i6 < spannableStringBuilder.length() - 1) {
                int i7 = i6 + 1;
                if (spannableStringBuilder.charAt(i6) == '\n' && spannableStringBuilder.charAt(i7) == ' ') {
                    spannableStringBuilder.delete(i7, i6 + 2);
                }
                i6 = i7;
            }
            if (spannableStringBuilder.length() > 0 && spannableStringBuilder.charAt(spannableStringBuilder.length() - 1) == ' ') {
                spannableStringBuilder.delete(spannableStringBuilder.length() - 1, spannableStringBuilder.length());
            }
            int i8 = 0;
            while (i8 < spannableStringBuilder.length() - 1) {
                int i9 = i8 + 1;
                if (spannableStringBuilder.charAt(i8) == ' ' && spannableStringBuilder.charAt(i9) == '\n') {
                    spannableStringBuilder.delete(i8, i9);
                }
                i8 = i9;
            }
            if (spannableStringBuilder.length() > 0 && spannableStringBuilder.charAt(spannableStringBuilder.length() - 1) == '\n') {
                spannableStringBuilder.delete(spannableStringBuilder.length() - 1, spannableStringBuilder.length());
            }
            c2788wg.e = c2682u22.c;
            c2788wg.f = c2682u22.d;
            c2788wg.g = c2682u22.e;
            c2788wg.h = c2682u22.b;
            c2788wg.l = c2682u22.f;
            c2788wg.k = c2682u22.i;
            c2788wg.j = c2682u22.h;
            c2788wg.n = c2682u22.j;
            arrayList2.add(c2788wg.a());
        }
        return arrayList2;
    }

    public m(C2596s2 c2596s2, HashMap map, HashMap map2, HashMap map3) {
        this.a = c2596s2;
        this.d = map2;
        this.e = map3;
        this.c = Collections.unmodifiableMap(map);
        TreeSet treeSet = new TreeSet();
        int i = 0;
        c2596s2.g(treeSet, false);
        long[] jArr = new long[treeSet.size()];
        Iterator it2 = treeSet.iterator();
        while (it2.hasNext()) {
            jArr[i] = ((Long) it2.next()).longValue();
            i++;
        }
        this.b = jArr;
    }

    @Override // com.google.android.gms.internal.ads.Pv
    public void zza(Throwable th) {
        Tq tq;
        C2601s7 c2601s7 = AbstractC2773w7.L5;
        r rVar = r.d;
        if (((Boolean) rVar.c.a(c2601s7)).booleanValue()) {
            A.m();
        }
        C1813Ze c1813Ze = (C1813Ze) this.d;
        final zze zzeVarL = AbstractC1972di.l(th, ((C2831xg) c1813Ze.j0.zzb()).l);
        Kp kp = (Kp) this.e;
        synchronized (kp) {
            try {
                kp.i = null;
                ((Zg) c1813Ze.b0.zzb()).m0(zzeVarL);
                if (((Boolean) rVar.c.a(AbstractC2773w7.i8)).booleanValue()) {
                    final int i = 0;
                    kp.b.execute(new Runnable(this) { // from class: com.google.android.gms.internal.ads.Ip
                        public final /* synthetic */ com.quizlet.data.interactor.folderwithcreator.m b;

                        {
                            this.b = this;
                        }

                        @Override // java.lang.Runnable
                        public final void run() {
                            switch (i) {
                                case 0:
                                    ((Kp) this.b.e).d.m0(zzeVarL);
                                    break;
                                default:
                                    ((Kp) this.b.e).e.m0(zzeVarL);
                                    break;
                            }
                        }
                    });
                    final int i2 = 1;
                    kp.b.execute(new Runnable(this) { // from class: com.google.android.gms.internal.ads.Ip
                        public final /* synthetic */ com.quizlet.data.interactor.folderwithcreator.m b;

                        {
                            this.b = this;
                        }

                        @Override // java.lang.Runnable
                        public final void run() {
                            switch (i2) {
                                case 0:
                                    ((Kp) this.b.e).d.m0(zzeVarL);
                                    break;
                                default:
                                    ((Kp) this.b.e).e.m0(zzeVarL);
                                    break;
                            }
                        }
                    });
                }
                AbstractC1795We.n(zzeVarL.a, "InterstitialAdLoader.onFailure", th);
                ((Rn) this.a).zza();
                if (!((Boolean) R7.c.o()).booleanValue() || (tq = (Tq) this.b) == null) {
                    Uq uq = kp.g;
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
            } catch (Throwable th2) {
                throw th2;
            }
        }
    }

    public m(com.perimeterx.mobile_sdk.session.m session, String pxUUID, String str, String str2, com.perimeterx.mobile_sdk.api_data.j activityReason) {
        Intrinsics.checkNotNullParameter(session, "session");
        Intrinsics.checkNotNullParameter(pxUUID, "pxUUID");
        Intrinsics.checkNotNullParameter(activityReason, "activityReason");
        this.a = session;
        this.b = pxUUID;
        this.c = str;
        this.d = str2;
        this.e = activityReason;
    }
}
