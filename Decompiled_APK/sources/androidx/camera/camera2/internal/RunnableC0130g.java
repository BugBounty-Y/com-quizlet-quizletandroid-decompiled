package androidx.camera.camera2.internal;

import android.content.Context;
import android.content.Intent;
import android.database.Cursor;
import android.graphics.Rect;
import android.hardware.camera2.CameraCaptureSession;
import android.os.Bundle;
import android.util.ArrayMap;
import android.util.Size;
import android.view.Surface;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewParent;
import android.webkit.ValueCallback;
import android.widget.ListView;
import androidx.camera.core.C0196t;
import androidx.camera.core.impl.AbstractC0171j;
import androidx.collection.C0208f;
import androidx.fragment.app.C1127d;
import androidx.fragment.app.C1145m;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.H0;
import androidx.fragment.app.x0;
import androidx.fragment.app.z0;
import androidx.work.impl.C1433e;
import androidx.work.impl.InterfaceC1430b;
import androidx.work.impl.WorkDatabase;
import androidx.work.impl.WorkDatabase_Impl;
import com.amazon.device.ads.DtbOmSdkSessionManager;
import com.appsflyer.internal.AFa1tSDK;
import com.appsflyer.internal.AFd1uSDK;
import com.appsflyer.internal.AFi1aSDK;
import com.appsflyer.internal.AFj1sSDK;
import com.braze.events.FeedUpdatedEvent;
import com.braze.ui.BrazeFeedFragment;
import com.braze.ui.inappmessage.views.InAppMessageImmersiveBaseView;
import com.comscore.streaming.EventType;
import com.facebook.FacebookException;
import com.facebook.login.CustomTabLoginMethodHandler;
import com.facebook.login.LoginClient;
import com.google.android.gms.internal.measurement.AbstractC3053s1;
import com.google.android.gms.internal.mlkit_vision_barcode.W6;
import com.google.android.gms.internal.mlkit_vision_barcode.X6;
import com.google.android.gms.internal.mlkit_vision_camera.A2;
import com.google.android.gms.internal.mlkit_vision_camera.C2;
import com.google.android.gms.internal.mlkit_vision_camera.W1;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executor;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.atomic.AtomicBoolean;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.camera.camera2.internal.g, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final /* synthetic */ class RunnableC0130g implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ Object d;

    public /* synthetic */ RunnableC0130g(androidx.camera.core.processing.c cVar, C0196t c0196t, androidx.concurrent.futures.i iVar) {
        this.a = 5;
        Map map = Collections.EMPTY_MAP;
        this.b = cVar;
        this.c = c0196t;
        this.d = iVar;
    }

    /* JADX WARN: Type inference failed for: r1v42, types: [kotlin.jvm.functions.Function0, kotlin.jvm.internal.r] */
    @Override // java.lang.Runnable
    public final void run() throws Throwable {
        Object obj;
        boolean zBooleanValue = true;
        Object objH = null;
        switch (this.a) {
            case 0:
                C0134k c0134k = ((C0137n) this.b).x;
                HashSet hashSet = (HashSet) c0134k.b;
                AbstractC0171j abstractC0171j = (AbstractC0171j) this.d;
                hashSet.add(abstractC0171j);
                ((ArrayMap) c0134k.c).put(abstractC0171j, (Executor) this.c);
                return;
            case 1:
                ((androidx.camera.camera2.internal.compat.f) this.b).a.onSurfacePrepared((CameraCaptureSession) this.c, (Surface) this.d);
                return;
            case 2:
                androidx.appcompat.app.K k = (androidx.appcompat.app.K) this.b;
                k.getClass();
                Objects.toString((C0135l) this.c);
                ((List) k.b).remove((androidx.concurrent.futures.l) this.d);
                return;
            case 3:
                androidx.lifecycle.Y y = (androidx.lifecycle.Y) ((com.quizlet.data.repository.activitycenter.b) this.b).b;
                androidx.camera.core.impl.U u = (androidx.camera.core.impl.U) this.c;
                if (u != null) {
                    y.k(u);
                }
                y.g((androidx.camera.core.impl.U) this.d);
                return;
            case 4:
                if (((androidx.camera.core.processing.c) this.b).j) {
                    ((Runnable) this.c).run();
                    return;
                } else {
                    ((Runnable) this.d).run();
                    return;
                }
            case 5:
                C0196t c0196t = (C0196t) this.c;
                Map map = Collections.EMPTY_MAP;
                androidx.concurrent.futures.i iVar = (androidx.concurrent.futures.i) this.d;
                androidx.camera.core.processing.c cVar = (androidx.camera.core.processing.c) this.b;
                cVar.getClass();
                try {
                    cVar.a.i(c0196t);
                    iVar.b(null);
                    return;
                } catch (RuntimeException e) {
                    iVar.d(e);
                    return;
                }
            case 6:
                ((io.ktor.client.plugins.api.d) this.b).h((androidx.camera.core.processing.k) this.c, (Map.Entry) this.d);
                return;
            case 7:
                C0196t c0196t2 = (C0196t) this.c;
                Map map2 = Collections.EMPTY_MAP;
                androidx.concurrent.futures.i iVar2 = (androidx.concurrent.futures.i) this.d;
                androidx.camera.core.processing.concurrent.e eVar = (androidx.camera.core.processing.concurrent.e) this.b;
                eVar.getClass();
                try {
                    eVar.a.i(c0196t2);
                    iVar2.b(null);
                    return;
                } catch (RuntimeException e2) {
                    iVar2.d(e2);
                    return;
                }
            case 8:
                if (((androidx.camera.core.processing.concurrent.e) this.b).f) {
                    ((Runnable) this.c).run();
                    return;
                } else {
                    ((Runnable) this.d).run();
                    return;
                }
            case 9:
                androidx.camera.view.p pVar = ((androidx.camera.view.q) this.b).f;
                androidx.camera.core.j0 j0Var = pVar.b;
                if (j0Var != null) {
                    Objects.toString(j0Var);
                    AbstractC3053s1.f(3, "SurfaceViewImpl");
                    pVar.b.c();
                }
                boolean z = pVar.g;
                androidx.camera.core.j0 j0Var2 = (androidx.camera.core.j0) this.c;
                if (z) {
                    pVar.g = false;
                    j0Var2.c();
                    j0Var2.i.b(null);
                    return;
                }
                pVar.b = j0Var2;
                pVar.d = (T) this.d;
                Size size = j0Var2.b;
                pVar.a = size;
                pVar.f = false;
                if (pVar.a()) {
                    return;
                }
                AbstractC3053s1.f(3, "SurfaceViewImpl");
                pVar.h.e.getHolder().setFixedSize(size.getWidth(), size.getHeight());
                return;
            case 10:
                androidx.emoji2.text.m mVar = (androidx.emoji2.text.m) this.b;
                X6 x6 = (X6) this.c;
                ThreadPoolExecutor threadPoolExecutor = (ThreadPoolExecutor) this.d;
                mVar.getClass();
                try {
                    androidx.emoji2.text.u uVarA = W6.a(mVar.a);
                    if (uVarA == null) {
                        throw new RuntimeException("EmojiCompat font provider not available on this device.");
                    }
                    androidx.emoji2.text.t tVar = (androidx.emoji2.text.t) ((androidx.emoji2.text.i) uVarA.b);
                    synchronized (tVar.d) {
                        tVar.f = threadPoolExecutor;
                    }
                    ((androidx.emoji2.text.i) uVarA.b).a(new androidx.emoji2.text.l(x6, threadPoolExecutor));
                    return;
                } catch (Throwable th) {
                    x6.c(th);
                    threadPoolExecutor.shutdown();
                    return;
                }
            case 11:
                ViewGroup container = (ViewGroup) this.b;
                Intrinsics.checkNotNullParameter(container, "$container");
                C1127d this$0 = (C1127d) this.d;
                Intrinsics.checkNotNullParameter(this$0, "this$0");
                container.endViewTransition((View) this.c);
                this$0.c.a.c(this$0);
                return;
            case 12:
                C1145m this$02 = (C1145m) this.d;
                Intrinsics.checkNotNullParameter(this$02, "this$0");
                Fragment inFragment = ((H0) this.b).c;
                Fragment outFragment = ((H0) this.c).c;
                boolean z2 = this$02.o;
                C0208f sharedElements = this$02.n;
                x0 x0Var = androidx.fragment.app.s0.a;
                Intrinsics.checkNotNullParameter(inFragment, "inFragment");
                Intrinsics.checkNotNullParameter(outFragment, "outFragment");
                Intrinsics.checkNotNullParameter(sharedElements, "sharedElements");
                if (z2) {
                    outFragment.getEnterTransitionCallback();
                    return;
                } else {
                    inFragment.getEnterTransitionCallback();
                    return;
                }
            case 13:
                z0 impl = (z0) this.b;
                Intrinsics.checkNotNullParameter(impl, "$impl");
                Rect lastInEpicenterRect = (Rect) this.d;
                Intrinsics.checkNotNullParameter(lastInEpicenterRect, "$lastInEpicenterRect");
                z0.j(lastInEpicenterRect, (View) this.c);
                return;
            case 14:
                androidx.concurrent.futures.i iVar3 = (androidx.concurrent.futures.i) this.c;
                Function0 function0 = (Function0) this.d;
                if (((AtomicBoolean) this.b).get()) {
                    return;
                }
                try {
                    iVar3.b(function0.invoke());
                    return;
                } catch (Throwable th2) {
                    iVar3.d(th2);
                    return;
                }
            case 15:
                androidx.concurrent.futures.i iVar4 = (androidx.concurrent.futures.i) this.c;
                ?? r1 = (kotlin.jvm.internal.r) this.d;
                if (((AtomicBoolean) this.b).get()) {
                    return;
                }
                try {
                    iVar4.b(r1.invoke());
                    return;
                } catch (Throwable th3) {
                    iVar4.d(th3);
                    return;
                }
            case 16:
                C1433e c1433e = (C1433e) this.b;
                androidx.concurrent.futures.l lVar = (androidx.concurrent.futures.l) this.c;
                androidx.work.impl.F f = (androidx.work.impl.F) this.d;
                c1433e.getClass();
                try {
                    zBooleanValue = ((Boolean) lVar.b.get()).booleanValue();
                } catch (InterruptedException | ExecutionException unused) {
                }
                synchronized (c1433e.k) {
                    try {
                        androidx.work.impl.model.j jVarA = A2.a(f.a);
                        String str = jVarA.a;
                        if (c1433e.c(str) == f) {
                            c1433e.b(str);
                        }
                        androidx.work.z.c().getClass();
                        Iterator it2 = c1433e.j.iterator();
                        while (it2.hasNext()) {
                            ((InterfaceC1430b) it2.next()).b(jVarA, zBooleanValue);
                        }
                    } finally {
                    }
                }
                return;
            case 17:
                ((C1433e) ((androidx.work.impl.model.c) this.b).b).h((androidx.work.impl.j) this.c, (com.google.android.gms.internal.appset.e) this.d);
                return;
            case 18:
                androidx.work.impl.model.t tVarU = ((WorkDatabase) this.b).u();
                tVarU.getClass();
                androidx.room.u uVarA2 = androidx.room.u.a(1, "SELECT id FROM workspec WHERE state NOT IN (2, 3, 5) AND id IN (SELECT work_spec_id FROM workname WHERE name=?)");
                uVarA2.g(1, (String) this.c);
                WorkDatabase_Impl workDatabase_Impl = (WorkDatabase_Impl) tVarU.a;
                workDatabase_Impl.b();
                Cursor cursorN = W1.N(workDatabase_Impl, uVarA2, false);
                try {
                    ArrayList arrayList = new ArrayList(cursorN.getCount());
                    while (cursorN.moveToNext()) {
                        arrayList.add(cursorN.getString(0));
                    }
                    cursorN.close();
                    uVarA2.i();
                    Iterator it3 = arrayList.iterator();
                    while (it3.hasNext()) {
                        C2.b((androidx.work.impl.r) this.d, (String) it3.next());
                    }
                    return;
                } catch (Throwable th4) {
                    cursorN.close();
                    uVarA2.i();
                    throw th4;
                }
            case 19:
                com.amazon.aps.ads.util.adview.e.a((com.amazon.aps.ads.util.adview.e) this.b, (String) this.c, (ValueCallback) this.d);
                return;
            case 20:
                ((DtbOmSdkSessionManager) this.b).lambda$addFriendlyObstruction$8((View) this.c, (com.iab.omid.library.amazon.adsession.g) this.d);
                return;
            case 21:
                ((AFa1tSDK) this.b).d_((Context) this.c, (Intent) this.d);
                return;
            case EventType.WINDOW_STATE /* 22 */:
                AFd1uSDK.getMediationNetwork((AFd1uSDK) this.b, (Throwable) this.c, (String) this.d);
                return;
            case EventType.AUDIO /* 23 */:
                ((AFj1sSDK) this.b).getMonetizationNetwork((AFi1aSDK) this.c, (Runnable) this.d);
                return;
            case EventType.VIDEO /* 24 */:
                ((BrazeFeedFragment) this.b).lambda$onViewCreated$2((FeedUpdatedEvent) this.c, (ListView) this.d);
                return;
            case EventType.SUBS /* 25 */:
                InAppMessageImmersiveBaseView.setLargerCloseButtonClickArea$lambda$8((View) this.b, (InAppMessageImmersiveBaseView) this.c, (ViewParent) this.d);
                return;
            case EventType.CDN /* 26 */:
                kotlin.jvm.internal.J billingClientWrapper = (kotlin.jvm.internal.J) this.b;
                com.facebook.appevents.iap.s billingClientVersion = (com.facebook.appevents.iap.s) this.c;
                Context context = (Context) this.d;
                if (com.facebook.internal.instrument.crashshield.a.b(com.facebook.appevents.iap.f.class)) {
                    return;
                }
                try {
                    Intrinsics.checkNotNullParameter(billingClientWrapper, "$billingClientWrapper");
                    Intrinsics.checkNotNullParameter(billingClientVersion, "$billingClientVersion");
                    Intrinsics.checkNotNullParameter(context, "$context");
                    ((com.facebook.appevents.iap.g) billingClientWrapper.a).a(com.facebook.appevents.iap.t.SUBS, new com.facebook.appevents.iap.e(billingClientVersion, context, 1));
                    return;
                } catch (Throwable th5) {
                    com.facebook.internal.instrument.crashshield.a.a(com.facebook.appevents.iap.f.class, th5);
                    return;
                }
            case 27:
                com.facebook.appevents.iap.l this$03 = (com.facebook.appevents.iap.l) this.b;
                com.facebook.appevents.iap.t productType = (com.facebook.appevents.iap.t) this.c;
                Runnable completionHandler = (Runnable) this.d;
                if (com.facebook.internal.instrument.crashshield.a.b(com.facebook.appevents.iap.l.class)) {
                    return;
                }
                try {
                    Intrinsics.checkNotNullParameter(this$03, "this$0");
                    Intrinsics.checkNotNullParameter(productType, "$productType");
                    Intrinsics.checkNotNullParameter(completionHandler, "$completionHandler");
                    Object objNewProxyInstance = Proxy.newProxyInstance(this$03.f.getClassLoader(), new Class[]{this$03.f}, new com.facebook.appevents.iap.i(this$03, productType, completionHandler));
                    Class cls = this$03.b;
                    Method method = this$03.j;
                    if (!com.facebook.internal.instrument.crashshield.a.b(this$03)) {
                        try {
                            objH = this$03.a;
                        } catch (Throwable th6) {
                            com.facebook.internal.instrument.crashshield.a.a(this$03, th6);
                        }
                    }
                    com.facebook.appevents.iap.u.h(cls, objH, method, productType.a, objNewProxyInstance);
                    return;
                } catch (Throwable th7) {
                    com.facebook.internal.instrument.crashshield.a.a(com.facebook.appevents.iap.l.class, th7);
                    return;
                }
            case 28:
                com.facebook.appevents.iap.m this$04 = (com.facebook.appevents.iap.m) this.b;
                com.facebook.appevents.iap.t productType2 = (com.facebook.appevents.iap.t) this.c;
                Runnable completionHandler2 = (Runnable) this.d;
                if (com.facebook.internal.instrument.crashshield.a.b(com.facebook.appevents.iap.m.class)) {
                    return;
                }
                try {
                    Intrinsics.checkNotNullParameter(this$04, "this$0");
                    Intrinsics.checkNotNullParameter(productType2, "$productType");
                    Intrinsics.checkNotNullParameter(completionHandler2, "$completionHandler");
                    Object objNewProxyInstance2 = Proxy.newProxyInstance(this$04.o.getClassLoader(), new Class[]{this$04.o}, new com.facebook.appevents.iap.k(this$04, new Object[]{productType2, completionHandler2}));
                    Class cls2 = this$04.b;
                    Method method2 = this$04.q;
                    if (com.facebook.internal.instrument.crashshield.a.b(this$04)) {
                        obj = null;
                    } else {
                        try {
                            obj = this$04.a;
                        } catch (Throwable th8) {
                            com.facebook.internal.instrument.crashshield.a.a(this$04, th8);
                        }
                    }
                    Class cls3 = this$04.k;
                    if (!com.facebook.internal.instrument.crashshield.a.b(this$04)) {
                        try {
                            objH = com.facebook.appevents.iap.u.h(cls3, com.facebook.appevents.iap.u.h(cls3, com.facebook.appevents.iap.u.h(this$04.i, null, this$04.r, new Object[0]), this$04.t, productType2.a), this$04.s, new Object[0]);
                        } catch (Throwable th9) {
                            com.facebook.internal.instrument.crashshield.a.a(this$04, th9);
                        }
                    }
                    com.facebook.appevents.iap.u.h(cls2, obj, method2, objH, objNewProxyInstance2);
                    return;
                } catch (Throwable th10) {
                    com.facebook.internal.instrument.crashshield.a.a(com.facebook.appevents.iap.m.class, th10);
                    return;
                }
            default:
                CustomTabLoginMethodHandler this$05 = (CustomTabLoginMethodHandler) this.b;
                Intrinsics.checkNotNullParameter(this$05, "this$0");
                LoginClient.Request request = (LoginClient.Request) this.c;
                Intrinsics.checkNotNullParameter(request, "$request");
                Bundle values = (Bundle) this.d;
                Intrinsics.checkNotNullParameter(values, "$values");
                try {
                    this$05.j(request, values);
                    this$05.p(request, values, null);
                    return;
                } catch (FacebookException e3) {
                    this$05.p(request, null, e3);
                    return;
                }
        }
    }

    public /* synthetic */ RunnableC0130g(androidx.camera.core.processing.concurrent.e eVar, C0196t c0196t, androidx.concurrent.futures.i iVar) {
        this.a = 7;
        Map map = Collections.EMPTY_MAP;
        this.b = eVar;
        this.c = c0196t;
        this.d = iVar;
    }

    public /* synthetic */ RunnableC0130g(Object obj, Object obj2, Object obj3, int i) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
        this.d = obj3;
    }

    /* JADX WARN: Multi-variable type inference failed */
    public /* synthetic */ RunnableC0130g(AtomicBoolean atomicBoolean, androidx.concurrent.futures.i iVar, Function0 function0) {
        this.a = 15;
        this.b = atomicBoolean;
        this.c = iVar;
        this.d = (kotlin.jvm.internal.r) function0;
    }
}
