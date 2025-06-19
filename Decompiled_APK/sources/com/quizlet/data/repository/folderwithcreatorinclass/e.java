package com.quizlet.data.repository.folderwithcreatorinclass;

import android.content.Context;
import android.content.Intent;
import android.graphics.Paint;
import android.graphics.Path;
import android.net.Uri;
import android.os.Build;
import android.os.IBinder;
import android.os.IInterface;
import android.os.RemoteException;
import android.view.View;
import android.widget.FrameLayout;
import androidx.camera.core.C0155g;
import androidx.camera.core.impl.InterfaceC0185y;
import androidx.camera.core.impl.utils.futures.h;
import androidx.camera.core.impl.utils.futures.i;
import androidx.camera.core.processing.j;
import androidx.camera.core.processing.m;
import androidx.lifecycle.B0;
import androidx.lifecycle.w0;
import androidx.lifecycle.y0;
import androidx.work.impl.model.l;
import com.google.android.gms.ads.internal.client.C1597h0;
import com.google.android.gms.ads.internal.client.E0;
import com.google.android.gms.ads.internal.client.InterfaceC1595g0;
import com.google.android.gms.ads.internal.client.r;
import com.google.android.gms.ads.internal.client.zze;
import com.google.android.gms.ads.s;
import com.google.android.gms.internal.ads.AbstractC1795We;
import com.google.android.gms.internal.ads.AbstractC1972di;
import com.google.android.gms.internal.ads.AbstractC2773w7;
import com.google.android.gms.internal.ads.C1882bf;
import com.google.android.gms.internal.ads.C2105gk;
import com.google.android.gms.internal.ads.C2688u8;
import com.google.android.gms.internal.ads.C2817x8;
import com.google.android.gms.internal.ads.C2903z8;
import com.google.android.gms.internal.ads.InterfaceC2860y8;
import com.google.android.gms.internal.ads.Lh;
import com.google.android.gms.internal.ads.Np;
import com.google.android.gms.internal.ads.Pp;
import com.google.android.gms.internal.ads.Pq;
import com.google.android.gms.internal.ads.Pv;
import com.google.android.gms.internal.ads.Qp;
import com.google.android.gms.internal.ads.R7;
import com.google.android.gms.internal.ads.Rn;
import com.google.android.gms.internal.ads.RunnableC2104gj;
import com.google.android.gms.internal.ads.RunnableC2793wl;
import com.google.android.gms.internal.ads.Tq;
import com.google.android.gms.internal.ads.Uq;
import com.google.android.gms.internal.ads.Y8;
import com.google.android.gms.internal.ads.Zg;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3242q6;
import com.google.android.gms.internal.mlkit_vision_barcode.S;
import com.google.android.gms.internal.mlkit_vision_barcode.T;
import com.google.android.gms.internal.mlkit_vision_camera.C1;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3424a4;
import com.google.android.material.circularreveal.f;
import com.google.android.material.circularreveal.g;
import com.quizlet.api.IQuizletApiClient;
import com.quizlet.api.model.CompatibilityCheck;
import com.quizlet.data.repository.folderwithcreatorinclass.e;
import com.quizlet.db.data.caches.UserInfoCache;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.eventlogger.features.qincentives.QIncentivesEventLogger;
import com.quizlet.generated.enums.EnumC4478e1;
import com.quizlet.quizletandroid.managers.u;
import io.reactivex.rxjava3.core.o;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.Executor;
import kotlin.Unit;
import kotlin.collections.A;
import kotlin.collections.B;
import kotlin.collections.C;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.C4950i;
import kotlin.jvm.internal.Intrinsics;
import kotlin.k;
import kotlinx.coroutines.AbstractC5040y;

/* loaded from: classes2.dex */
public final class e implements k, Pv {
    public final Object a;
    public final Object b;
    public final Object c;
    public Object d;
    public Object e;

    public e(Qp qp, Rn rn, Tq tq, Pq pq, Pp pp) {
        this.a = rn;
        this.b = tq;
        this.c = pq;
        this.d = pp;
        this.e = qp;
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0016  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object a(com.quizlet.data.repository.folderwithcreatorinclass.e r4, kotlin.coroutines.jvm.internal.c r5) {
        /*
            r4.getClass()
            boolean r0 = r5 instanceof com.quizlet.features.infra.compatibility.c
            if (r0 == 0) goto L16
            r0 = r5
            com.quizlet.features.infra.compatibility.c r0 = (com.quizlet.features.infra.compatibility.c) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L16
            int r1 = r1 - r2
            r0.l = r1
            goto L1b
        L16:
            com.quizlet.features.infra.compatibility.c r0 = new com.quizlet.features.infra.compatibility.c
            r0.<init>(r4, r5)
        L1b:
            java.lang.Object r5 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L32
            if (r2 != r3) goto L2a
            androidx.glance.appwidget.protobuf.Z.e(r5)
            goto L48
        L2a:
            java.lang.IllegalStateException r4 = new java.lang.IllegalStateException
            java.lang.String r5 = "call to 'resume' before 'invoke' with coroutine"
            r4.<init>(r5)
            throw r4
        L32:
            androidx.glance.appwidget.protobuf.Z.e(r5)
            java.lang.String r5 = android.os.Build.VERSION.RELEASE
            java.lang.Object r4 = r4.b
            com.quizlet.api.IQuizletApiClient r4 = (com.quizlet.api.IQuizletApiClient) r4
            io.reactivex.rxjava3.internal.operators.single.g r4 = r4.t()
            r0.l = r3
            java.lang.Object r5 = com.google.android.gms.internal.mlkit_vision_camera.I1.b(r4, r0)
            if (r5 != r1) goto L48
            return r1
        L48:
            java.lang.String r4 = "await(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r5, r4)
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.repository.folderwithcreatorinclass.e.a(com.quizlet.data.repository.folderwithcreatorinclass.e, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public static final com.quizlet.features.infra.compatibility.a b(final e eVar, CompatibilityCheck compatibilityCheck) {
        eVar.getClass();
        Function0 function0 = null;
        if (compatibilityCheck == null) {
            return null;
        }
        String userMessage = compatibilityCheck.getUserMessage();
        String userMessageTitle = compatibilityCheck.getUserMessageTitle();
        String action = compatibilityCheck.getAction();
        if (Intrinsics.b(action, "logout")) {
            if (((UserInfoCache) eVar.a).b()) {
                final int i = 0;
                function0 = new Function0(eVar) { // from class: com.quizlet.features.infra.compatibility.b
                    public final /* synthetic */ e b;

                    {
                        this.b = eVar;
                    }

                    @Override // kotlin.jvm.functions.Function0
                    public final Object invoke() {
                        switch (i) {
                            case 0:
                                u uVar = (u) this.b.c;
                                uVar.a();
                                uVar.u.startActivity((Intent) uVar.i.get());
                                break;
                            default:
                                Context context = (Context) this.b.d;
                                Intent intent = new Intent("android.intent.action.VIEW", Uri.parse("market://details?id=com.quizlet.quizletandroid"));
                                Intent intent2 = new Intent("android.intent.action.VIEW", Uri.parse("https://play.google.com/store/apps/details?id=com.quizlet.quizletandroid"));
                                if (intent.resolveActivity(context.getPackageManager()) != null) {
                                    context.startActivity(intent.addFlags(268435456));
                                } else if (intent2.resolveActivity(context.getPackageManager()) != null) {
                                    context.startActivity(intent2.addFlags(268435456));
                                }
                                break;
                        }
                        return Unit.a;
                    }
                };
            }
        } else if (Intrinsics.b(action, "app_store_upgrade")) {
            final int i2 = 1;
            function0 = new Function0(eVar) { // from class: com.quizlet.features.infra.compatibility.b
                public final /* synthetic */ e b;

                {
                    this.b = eVar;
                }

                @Override // kotlin.jvm.functions.Function0
                public final Object invoke() {
                    switch (i2) {
                        case 0:
                            u uVar = (u) this.b.c;
                            uVar.a();
                            uVar.u.startActivity((Intent) uVar.i.get());
                            break;
                        default:
                            Context context = (Context) this.b.d;
                            Intent intent = new Intent("android.intent.action.VIEW", Uri.parse("market://details?id=com.quizlet.quizletandroid"));
                            Intent intent2 = new Intent("android.intent.action.VIEW", Uri.parse("https://play.google.com/store/apps/details?id=com.quizlet.quizletandroid"));
                            if (intent.resolveActivity(context.getPackageManager()) != null) {
                                context.startActivity(intent.addFlags(268435456));
                            } else if (intent2.resolveActivity(context.getPackageManager()) != null) {
                                context.startActivity(intent2.addFlags(268435456));
                            }
                            break;
                    }
                    return Unit.a;
                }
            };
        }
        Intrinsics.d(userMessage);
        Intrinsics.d(userMessageTitle);
        return new com.quizlet.features.infra.compatibility.a(userMessage, userMessageTitle, function0);
    }

    public static List h(ArrayList arrayList, com.quizlet.search.data.a aVar) {
        return !arrayList.isEmpty() ? C.r(B.j(Arrays.copyOf(new List[]{A.b(new com.quizlet.search.data.b(aVar)), arrayList}, 2))) : arrayList;
    }

    @Override // com.google.android.gms.internal.ads.Pv
    /* renamed from: c */
    public void mo15c(Object obj) {
        Tq tq;
        Qp qp = (Qp) this.e;
        C2105gk c2105gk = (C2105gk) obj;
        synchronized (qp) {
            try {
                ((Lh) c2105gk.g.a.b).e = qp.d;
                ((Rn) this.a).o(c2105gk);
                Executor executor = qp.b;
                Np np = qp.d;
                Objects.requireNonNull(np);
                executor.execute(new RunnableC2104gj(np, 15));
                qp.d.j();
                if (!((Boolean) R7.c.o()).booleanValue() || (tq = (Tq) this.b) == null) {
                    Uq uq = qp.g;
                    Pq pq = (Pq) this.c;
                    pq.f(c2105gk.a.b);
                    pq.I(c2105gk.f.a);
                    pq.h(true);
                    uq.b(pq.l());
                } else {
                    tq.g(c2105gk.a.b);
                    tq.e(c2105gk.f.a);
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

    public void d(InterfaceC0185y interfaceC0185y, InterfaceC0185y interfaceC0185y2, androidx.camera.core.processing.k kVar, androidx.camera.core.processing.k kVar2, Map.Entry entry) {
        androidx.camera.core.processing.k kVar3 = (androidx.camera.core.processing.k) entry.getValue();
        C0155g c0155g = new C0155g(kVar.g.a, ((androidx.camera.core.processing.concurrent.a) entry.getKey()).a.d, kVar.c ? interfaceC0185y : null, ((androidx.camera.core.processing.concurrent.a) entry.getKey()).a.f, ((androidx.camera.core.processing.concurrent.a) entry.getKey()).a.g);
        C0155g c0155g2 = new C0155g(kVar2.g.a, ((androidx.camera.core.processing.concurrent.a) entry.getKey()).b.d, kVar2.c ? interfaceC0185y2 : null, ((androidx.camera.core.processing.concurrent.a) entry.getKey()).b.f, ((androidx.camera.core.processing.concurrent.a) entry.getKey()).b.g);
        androidx.camera.core.processing.util.b bVar = ((androidx.camera.core.processing.concurrent.a) entry.getKey()).a;
        kVar3.getClass();
        S.d();
        kVar3.a();
        AbstractC3242q6.h("Consumer can only be linked once.", !kVar3.j);
        kVar3.j = true;
        j jVar = kVar3.l;
        androidx.camera.core.impl.utils.futures.b bVarF = i.f(jVar.c(), new androidx.camera.core.processing.i(kVar3, jVar, bVar.c, c0155g, c0155g2), T.e());
        bVarF.a(new h(0, bVarF, new com.quizlet.data.repository.qclass.c((Object) this, false, (Object) kVar3, 2)), T.e());
    }

    /* JADX WARN: Removed duplicated region for block: B:14:0x0040  */
    /* JADX WARN: Type inference failed for: r1v2, types: [android.widget.FrameLayout, com.google.android.material.circularreveal.g] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void e(android.graphics.Canvas r9) {
        /*
            r8 = this;
            java.lang.Object r0 = r8.d
            com.google.android.material.circularreveal.f r0 = (com.google.android.material.circularreveal.f) r0
            if (r0 == 0) goto L12
            float r0 = r0.c
            r1 = 2139095039(0x7f7fffff, float:3.4028235E38)
            int r0 = (r0 > r1 ? 1 : (r0 == r1 ? 0 : -1))
            if (r0 != 0) goto L10
            goto L12
        L10:
            r0 = 0
            goto L13
        L12:
            r0 = 1
        L13:
            java.lang.Object r1 = r8.c
            r7 = r1
            android.graphics.Paint r7 = (android.graphics.Paint) r7
            java.lang.Object r1 = r8.a
            android.widget.FrameLayout r1 = (android.widget.FrameLayout) r1
            java.lang.Object r2 = r8.b
            android.view.View r2 = (android.view.View) r2
            if (r0 != 0) goto L42
            r1.c(r9)
            int r0 = r7.getColor()
            int r0 = android.graphics.Color.alpha(r0)
            if (r0 == 0) goto L40
            int r0 = r2.getWidth()
            float r5 = (float) r0
            int r0 = r2.getHeight()
            float r6 = (float) r0
            r3 = 0
            r4 = 0
            r2 = r9
            r2.drawRect(r3, r4, r5, r6, r7)
            goto L5f
        L40:
            r2 = r9
            goto L5f
        L42:
            r1.c(r9)
            int r0 = r7.getColor()
            int r0 = android.graphics.Color.alpha(r0)
            if (r0 == 0) goto L40
            int r0 = r2.getWidth()
            float r5 = (float) r0
            int r0 = r2.getHeight()
            float r6 = (float) r0
            r3 = 0
            r4 = 0
            r2 = r9
            r2.drawRect(r3, r4, r5, r6, r7)
        L5f:
            java.lang.Object r9 = r8.e
            android.graphics.drawable.Drawable r9 = (android.graphics.drawable.Drawable) r9
            if (r9 == 0) goto L9a
            java.lang.Object r0 = r8.d
            com.google.android.material.circularreveal.f r0 = (com.google.android.material.circularreveal.f) r0
            if (r0 == 0) goto L9a
            android.graphics.Rect r9 = r9.getBounds()
            java.lang.Object r0 = r8.d
            com.google.android.material.circularreveal.f r0 = (com.google.android.material.circularreveal.f) r0
            float r0 = r0.a
            int r1 = r9.width()
            float r1 = (float) r1
            r3 = 1073741824(0x40000000, float:2.0)
            float r1 = r1 / r3
            float r0 = r0 - r1
            java.lang.Object r1 = r8.d
            com.google.android.material.circularreveal.f r1 = (com.google.android.material.circularreveal.f) r1
            float r1 = r1.b
            int r9 = r9.height()
            float r9 = (float) r9
            float r9 = r9 / r3
            float r1 = r1 - r9
            r2.translate(r0, r1)
            java.lang.Object r9 = r8.e
            android.graphics.drawable.Drawable r9 = (android.graphics.drawable.Drawable) r9
            r9.draw(r2)
            float r9 = -r0
            float r0 = -r1
            r2.translate(r9, r0)
        L9a:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.repository.folderwithcreatorinclass.e.e(android.graphics.Canvas):void");
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:42:0x0104  */
    /* JADX WARN: Removed duplicated region for block: B:45:0x0117  */
    /* JADX WARN: Removed duplicated region for block: B:46:0x0119 A[Catch: Exception -> 0x0056, TryCatch #1 {Exception -> 0x0056, blocks: (B:43:0x0106, B:55:0x013c, B:57:0x0140, B:59:0x0147, B:58:0x0143, B:46:0x0119, B:49:0x0124, B:50:0x0129, B:53:0x0136, B:21:0x0051, B:39:0x00ed, B:26:0x0062), top: B:69:0x0029 }] */
    /* JADX WARN: Removed duplicated region for block: B:57:0x0140 A[Catch: Exception -> 0x0056, TryCatch #1 {Exception -> 0x0056, blocks: (B:43:0x0106, B:55:0x013c, B:57:0x0140, B:59:0x0147, B:58:0x0143, B:46:0x0119, B:49:0x0124, B:50:0x0129, B:53:0x0136, B:21:0x0051, B:39:0x00ed, B:26:0x0062), top: B:69:0x0029 }] */
    /* JADX WARN: Removed duplicated region for block: B:58:0x0143 A[Catch: Exception -> 0x0056, TryCatch #1 {Exception -> 0x0056, blocks: (B:43:0x0106, B:55:0x013c, B:57:0x0140, B:59:0x0147, B:58:0x0143, B:46:0x0119, B:49:0x0124, B:50:0x0129, B:53:0x0136, B:21:0x0051, B:39:0x00ed, B:26:0x0062), top: B:69:0x0029 }] */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0019  */
    /* JADX WARN: Type inference failed for: r6v0, types: [int] */
    /* JADX WARN: Type inference failed for: r6v1 */
    /* JADX WARN: Type inference failed for: r6v11 */
    /* JADX WARN: Type inference failed for: r6v12 */
    /* JADX WARN: Type inference failed for: r6v7, types: [com.quizlet.db.data.models.persisted.DBGroup] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object f(java.lang.String r18, java.lang.String r19, kotlin.coroutines.jvm.internal.c r20, boolean r21) throws com.quizlet.data.exceptions.classcreation.ClassCreationMissingTitleException {
        /*
            Method dump skipped, instructions count: 376
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.repository.folderwithcreatorinclass.e.f(java.lang.String, java.lang.String, kotlin.coroutines.jvm.internal.c, boolean):java.lang.Object");
    }

    public void g(f fVar) {
        View view = (View) this.b;
        if (fVar == null) {
            this.d = null;
        } else {
            f fVar2 = (f) this.d;
            if (fVar2 == null) {
                this.d = new f(fVar);
            } else {
                float f = fVar.a;
                float f2 = fVar.b;
                float f3 = fVar.c;
                fVar2.a = f;
                fVar2.b = f2;
                fVar2.c = f3;
            }
            if (fVar.c + 1.0E-4f >= AbstractC3424a4.b(fVar.a, fVar.b, view.getWidth(), view.getHeight())) {
                ((f) this.d).c = Float.MAX_VALUE;
            }
        }
        view.invalidate();
    }

    @Override // kotlin.k
    public Object getValue() {
        w0 w0Var = (w0) this.e;
        if (w0Var != null) {
            return w0Var;
        }
        B0 store = (B0) ((Function0) this.b).invoke();
        y0 factory = (y0) ((Function0) this.c).invoke();
        androidx.lifecycle.viewmodel.c defaultCreationExtras = (androidx.lifecycle.viewmodel.c) ((Function0) this.d).invoke();
        Intrinsics.checkNotNullParameter(store, "store");
        Intrinsics.checkNotNullParameter(factory, "factory");
        Intrinsics.checkNotNullParameter(defaultCreationExtras, "extras");
        Intrinsics.checkNotNullParameter(store, "store");
        Intrinsics.checkNotNullParameter(factory, "factory");
        Intrinsics.checkNotNullParameter(defaultCreationExtras, "defaultCreationExtras");
        com.quizlet.data.repository.metering.j jVar = new com.quizlet.data.repository.metering.j(store, factory, defaultCreationExtras);
        C4950i modelClass = (C4950i) this.a;
        Intrinsics.checkNotNullParameter(modelClass, "modelClass");
        Intrinsics.checkNotNullParameter(modelClass, "modelClass");
        String strB = C1.b(modelClass);
        if (strB == null) {
            throw new IllegalArgumentException("Local and anonymous classes can not be ViewModels");
        }
        w0 w0VarE = jVar.e(modelClass, "androidx.lifecycle.ViewModelProvider.DefaultKey:".concat(strB));
        this.e = w0VarE;
        return w0VarE;
    }

    @Override // kotlin.k
    public boolean isInitialized() {
        return ((w0) this.e) != null;
    }

    @Override // com.google.android.gms.internal.ads.Pv
    public void zza(Throwable th) {
        Tq tq;
        if (((Boolean) r.d.c.a(AbstractC2773w7.L5)).booleanValue()) {
            com.google.android.gms.ads.internal.util.A.m();
        }
        Qp qp = (Qp) this.e;
        C1882bf c1882bf = (C1882bf) qp.e.j();
        zze zzeVarL = c1882bf == null ? AbstractC1972di.l(th, null) : AbstractC1972di.l(th, c1882bf.zzb().l);
        synchronized (qp) {
            try {
                if (c1882bf != null) {
                    ((Zg) c1882bf.c0.zzb()).m0(zzeVarL);
                    qp.b.execute(new RunnableC2793wl(9, this, zzeVarL));
                } else {
                    qp.d.m0(zzeVarL);
                    qp.b((Pp) this.d).g().zzb().f.g();
                }
                AbstractC1795We.n(zzeVarL.a, "RewardedAdLoader.onFailure", th);
                ((Rn) this.a).zza();
                if (!((Boolean) R7.c.o()).booleanValue() || (tq = (Tq) this.b) == null) {
                    Uq uq = qp.g;
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

    public /* synthetic */ e(Object obj, Object obj2, Object obj3, Object obj4, Object obj5) {
        this.a = obj;
        this.b = obj2;
        this.c = obj3;
        this.d = obj4;
        this.e = obj5;
    }

    public e(Y8 y8) {
        InterfaceC2860y8 c2817x8;
        IBinder iBinder;
        this.b = new ArrayList();
        this.d = new s();
        this.e = new ArrayList();
        this.a = y8;
        C2903z8 c2903z8 = null;
        try {
            List listC = y8.c();
            if (listC != null) {
                for (Object obj : listC) {
                    if (!(obj instanceof IBinder) || (iBinder = (IBinder) obj) == null) {
                        c2817x8 = null;
                    } else {
                        IInterface iInterfaceQueryLocalInterface = iBinder.queryLocalInterface("com.google.android.gms.ads.internal.formats.client.INativeAdImage");
                        c2817x8 = iInterfaceQueryLocalInterface instanceof InterfaceC2860y8 ? (InterfaceC2860y8) iInterfaceQueryLocalInterface : new C2817x8(iBinder);
                    }
                    if (c2817x8 != null) {
                        ((ArrayList) this.b).add(new C2903z8(c2817x8));
                    }
                }
            }
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.i.f("", e);
        }
        try {
            List listD = ((Y8) this.a).d();
            if (listD != null) {
                for (Object obj2 : listD) {
                    InterfaceC1595g0 interfaceC1595g0E4 = obj2 instanceof IBinder ? E0.e4((IBinder) obj2) : null;
                    if (interfaceC1595g0E4 != null) {
                        ((ArrayList) this.e).add(new C1597h0(interfaceC1595g0E4));
                    }
                }
            }
        } catch (RemoteException e2) {
            com.google.android.gms.ads.internal.util.client.i.f("", e2);
        }
        try {
            InterfaceC2860y8 interfaceC2860y8N = ((Y8) this.a).n();
            if (interfaceC2860y8N != null) {
                c2903z8 = new C2903z8(interfaceC2860y8N);
            }
        } catch (RemoteException e3) {
            com.google.android.gms.ads.internal.util.client.i.f("", e3);
        }
        this.c = c2903z8;
        try {
            if (((Y8) this.a).zzi() != null) {
                new C2688u8(((Y8) this.a).zzi(), 0);
            }
        } catch (RemoteException e4) {
            com.google.android.gms.ads.internal.util.client.i.f("", e4);
        }
    }

    public e(com.quizlet.quizletandroid.ui.common.ads.prebid.creators.c repository, com.google.firebase.crashlytics.internal.settings.b preferencesRepository, QIncentivesEventLogger eventLogger, kotlinx.coroutines.internal.d ioScope, AbstractC5040y ioDispatcher) {
        Intrinsics.checkNotNullParameter(repository, "repository");
        Intrinsics.checkNotNullParameter(preferencesRepository, "preferencesRepository");
        Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
        Intrinsics.checkNotNullParameter(ioScope, "ioScope");
        Intrinsics.checkNotNullParameter(ioDispatcher, "ioDispatcher");
        this.a = repository;
        this.b = preferencesRepository;
        this.c = eventLogger;
        this.d = ioScope;
        this.e = ioDispatcher;
    }

    public e(com.quizlet.infra.legacysyncengine.net.f syncDispatcher, com.quizlet.infra.legacysyncengine.managers.d loggedInUserManager, EventLogger eventLogger, com.quizlet.infra.legacysyncengine.managers.i modelSaveManager, com.quizlet.data.repository.classmembership.c classRepository) {
        Intrinsics.checkNotNullParameter(syncDispatcher, "syncDispatcher");
        Intrinsics.checkNotNullParameter(loggedInUserManager, "loggedInUserManager");
        Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
        Intrinsics.checkNotNullParameter(modelSaveManager, "modelSaveManager");
        Intrinsics.checkNotNullParameter(classRepository, "classRepository");
        this.a = syncDispatcher;
        this.b = loggedInUserManager;
        this.c = eventLogger;
        this.d = modelSaveManager;
        this.e = classRepository;
    }

    public e(l factory, com.quizlet.local.ormlite.models.bookmark.a classFolderLocal, com.quizlet.local.ormlite.models.bookmark.a folderWithCreatorLocal, com.quizlet.data.connectivity.a networkStatus, org.slf4j.b logger) {
        Intrinsics.checkNotNullParameter(factory, "factory");
        Intrinsics.checkNotNullParameter(classFolderLocal, "classFolderLocal");
        Intrinsics.checkNotNullParameter(folderWithCreatorLocal, "folderWithCreatorLocal");
        Intrinsics.checkNotNullParameter(networkStatus, "networkStatus");
        Intrinsics.checkNotNullParameter(logger, "logger");
        this.a = factory;
        this.b = classFolderLocal;
        this.c = folderWithCreatorLocal;
        this.d = networkStatus;
        this.e = logger;
    }

    public e(IQuizletApiClient quizletApiClient, com.quizlet.infra.legacysyncengine.net.c loader, com.quizlet.infra.legacysyncengine.managers.h serverModelSaveManager, o mainThreadScheduler, o networkThreadScheduler) {
        Intrinsics.checkNotNullParameter(quizletApiClient, "quizletApiClient");
        Intrinsics.checkNotNullParameter(loader, "loader");
        Intrinsics.checkNotNullParameter(serverModelSaveManager, "serverModelSaveManager");
        Intrinsics.checkNotNullParameter(mainThreadScheduler, "mainThreadScheduler");
        Intrinsics.checkNotNullParameter(networkThreadScheduler, "networkThreadScheduler");
        this.a = quizletApiClient;
        this.b = loader;
        this.c = serverModelSaveManager;
        this.d = mainThreadScheduler;
        this.e = networkThreadScheduler;
    }

    public e(com.google.firebase.crashlytics.internal.common.j searchAllResultsUseCase, androidx.work.impl.model.c userProperties, com.quizlet.remote.model.set.d searchShortcutsUseCase, AbstractC5040y ioDispatcher) {
        Intrinsics.checkNotNullParameter(searchAllResultsUseCase, "searchAllResultsUseCase");
        Intrinsics.checkNotNullParameter(userProperties, "userProperties");
        Intrinsics.checkNotNullParameter(searchShortcutsUseCase, "searchShortcutsUseCase");
        Intrinsics.checkNotNullParameter(ioDispatcher, "ioDispatcher");
        this.a = searchAllResultsUseCase;
        this.b = userProperties;
        this.c = searchShortcutsUseCase;
        this.d = ioDispatcher;
        this.e = B.j(EnumC4478e1.SET, EnumC4478e1.TEXTBOOK, EnumC4478e1.QUESTION, EnumC4478e1.USER, EnumC4478e1.CLAZZ);
    }

    public e(UserInfoCache userInfoCache, IQuizletApiClient quizletApiClient, u logoutManager, com.quizlet.quizletandroid.util.d compatibilityIntentsUtil, com.quizlet.shared.usecase.folderstudymaterials.d sslProviderInstaller, Context context, AbstractC5040y ioDispatcher) {
        String versionRelease = Build.VERSION.RELEASE;
        Intrinsics.checkNotNullParameter(userInfoCache, "userInfoCache");
        Intrinsics.checkNotNullParameter(quizletApiClient, "quizletApiClient");
        Intrinsics.checkNotNullParameter(logoutManager, "logoutManager");
        Intrinsics.checkNotNullParameter(compatibilityIntentsUtil, "compatibilityIntentsUtil");
        Intrinsics.checkNotNullParameter(sslProviderInstaller, "sslProviderInstaller");
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter("9.34.3", "versionName");
        Intrinsics.checkNotNullParameter(versionRelease, "versionRelease");
        Intrinsics.checkNotNullParameter(ioDispatcher, "ioDispatcher");
        this.a = userInfoCache;
        this.b = quizletApiClient;
        this.c = logoutManager;
        this.d = context;
        this.e = ioDispatcher;
    }

    public e(C4950i viewModelClass, Function0 storeProducer, Function0 factoryProducer, Function0 extrasProducer) {
        Intrinsics.checkNotNullParameter(viewModelClass, "viewModelClass");
        Intrinsics.checkNotNullParameter(storeProducer, "storeProducer");
        Intrinsics.checkNotNullParameter(factoryProducer, "factoryProducer");
        Intrinsics.checkNotNullParameter(extrasProducer, "extrasProducer");
        this.a = viewModelClass;
        this.b = storeProducer;
        this.c = factoryProducer;
        this.d = extrasProducer;
    }

    public e(InterfaceC0185y interfaceC0185y, InterfaceC0185y interfaceC0185y2, m mVar) {
        this.b = interfaceC0185y;
        this.c = interfaceC0185y2;
        this.a = mVar;
    }

    /* JADX WARN: Multi-variable type inference failed */
    public e(g gVar) {
        this.a = (FrameLayout) gVar;
        View view = (View) gVar;
        this.b = view;
        view.setWillNotDraw(false);
        new Path();
        new Paint(7);
        Paint paint = new Paint(1);
        this.c = paint;
        paint.setColor(0);
    }
}
