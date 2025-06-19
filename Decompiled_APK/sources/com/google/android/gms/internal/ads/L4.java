package com.google.android.gms.internal.ads;

import android.app.Activity;
import android.content.Context;
import android.os.SystemClock;
import android.util.DisplayMetrics;
import android.view.MotionEvent;
import android.view.View;
import com.google.android.gms.ads.internal.client.C1608n;
import com.skydoves.balloon.internals.DefinitionKt;
import java.io.File;
import java.lang.ref.WeakReference;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;

/* loaded from: classes2.dex */
public final class L4 implements N4 {
    public static L4 r;
    public final Context a;
    public final As b;
    public final Bs c;
    public final Cs d;
    public final androidx.compose.ui.node.V e;
    public final androidx.browser.customtabs.k f;
    public final ExecutorService g;
    public final C1 h;
    public final C2039f5 j;
    public final J k;
    public final C2881yn l;
    public volatile boolean o;
    public volatile boolean p;
    public final int q;
    public volatile long m = 0;
    public final Object n = new Object();
    public final CountDownLatch i = new CountDownLatch(1);

    public L4(Context context, androidx.browser.customtabs.k kVar, As as, Bs bs, Cs cs, androidx.compose.ui.node.V v, ExecutorService executorService, C1 c1, int i, C2039f5 c2039f5, J j, C2881yn c2881yn) {
        this.p = false;
        this.a = context;
        this.f = kVar;
        this.b = as;
        this.c = bs;
        this.d = cs;
        this.e = v;
        this.g = executorService;
        this.q = i;
        this.j = c2039f5;
        this.k = j;
        this.l = c2881yn;
        this.p = false;
        this.h = new C1(c1);
    }

    /* JADX WARN: Removed duplicated region for block: B:49:0x00f8 A[Catch: all -> 0x0098, zzgzh -> 0x009b, TryCatch #2 {zzgzh -> 0x009b, blocks: (B:6:0x001d, B:8:0x002b, B:12:0x0031, B:13:0x003f, B:15:0x004d, B:17:0x005b, B:20:0x0068, B:32:0x009e, B:36:0x00b7, B:42:0x00d0, B:43:0x00dd, B:45:0x00e3, B:47:0x00eb, B:48:0x00ee, B:39:0x00c1, B:40:0x00c8, B:23:0x006f, B:25:0x0085, B:49:0x00f8, B:50:0x0105, B:51:0x0112), top: B:58:0x001d, outer: #0 }] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static void j(com.google.android.gms.internal.ads.L4 r7) {
        /*
            Method dump skipped, instructions count: 309
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.L4.j(com.google.android.gms.internal.ads.L4):void");
    }

    public static synchronized L4 m(Context context, ExecutorService executorService, C2414ns c2414ns, boolean z) {
        try {
            if (r == null) {
                androidx.browser.customtabs.k kVarK = androidx.browser.customtabs.k.k(context, executorService, z);
                C2601s7 c2601s7 = AbstractC2773w7.x3;
                com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
                S4 s4I = ((Boolean) rVar.c.a(c2601s7)).booleanValue() ? S4.i(context) : null;
                C2039f5 c2039f5A = ((Boolean) rVar.c.a(AbstractC2773w7.y3)).booleanValue() ? C2039f5.a(context, executorService) : null;
                J j = ((Boolean) rVar.c.a(AbstractC2773w7.M2)).booleanValue() ? new J() : null;
                C2881yn c2881yn = ((Boolean) rVar.c.a(AbstractC2773w7.U2)).booleanValue() ? new C2881yn(5) : null;
                com.quizlet.data.repository.achievements.h hVar = new com.quizlet.data.repository.achievements.h();
                hVar.a = context;
                hVar.b = executorService;
                hVar.c = kVarK;
                com.google.android.gms.tasks.m mVarG = com.google.android.gms.internal.mlkit_vision_common.S3.g(executorService, new CallableC2154hp(hVar, 3));
                mVarG.c(executorService, new S4(hVar, 29));
                hVar.d = mVarG;
                V4 v4 = new V4(context);
                androidx.compose.ui.node.V v = new androidx.compose.ui.node.V(c2414ns, hVar, new ViewOnAttachStateChangeListenerC1952d5(context, v4), v4, s4I, c2039f5A, j, c2881yn, 4);
                int iL = AbstractC1981ds.l(context, kVarK);
                C1 c1 = new C1(4);
                L4 l4 = new L4(context, kVarK, new As(context, iL), new Bs(context, iL, new Ts(kVarK, 5), ((Boolean) rVar.c.a(AbstractC2773w7.w2)).booleanValue()), new Cs(context, v, kVarK, c1), v, executorService, c1, iL, c2039f5A, j, c2881yn);
                r = l4;
                l4.k();
                r.l();
            }
        } catch (Throwable th) {
            throw th;
        }
        return r;
    }

    @Override // com.google.android.gms.internal.ads.N4
    public final void a(View view) {
        ((ViewOnAttachStateChangeListenerC1952d5) this.e.d).a(view);
    }

    @Override // com.google.android.gms.internal.ads.N4
    public final String b(Context context) {
        String strM;
        C2039f5 c2039f5 = this.j;
        if (c2039f5 != null && c2039f5.d) {
            c2039f5.b = System.currentTimeMillis();
        }
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.M2)).booleanValue()) {
            J j = this.k;
            j.b = j.a;
            j.a = SystemClock.uptimeMillis();
        }
        l();
        com.quizlet.data.repository.explanations.exercise.b bVarA = this.d.a();
        if (bVarA == null) {
            return "";
        }
        long jCurrentTimeMillis = System.currentTimeMillis();
        synchronized (bVarA) {
            HashMap mapM = ((androidx.compose.ui.node.V) bVarA.c).m();
            mapM.put("f", "q");
            mapM.put("ctx", context);
            mapM.put("aid", null);
            strM = com.quizlet.data.repository.explanations.exercise.b.m(bVarA.n(mapM));
        }
        this.f.u(com.pubmatic.sdk.common.h.INVALID_REWARD_SELECTED, System.currentTimeMillis() - jCurrentTimeMillis, null, strM, null);
        return strM;
    }

    @Override // com.google.android.gms.internal.ads.N4
    public final void c(StackTraceElement[] stackTraceElementArr) {
        C2881yn c2881yn = this.l;
        if (c2881yn != null) {
            c2881yn.b = new ArrayList(Arrays.asList(stackTraceElementArr));
        }
    }

    @Override // com.google.android.gms.internal.ads.N4
    public final String d(Context context, View view, String str) {
        return f(context, str, view, null);
    }

    @Override // com.google.android.gms.internal.ads.N4
    public final String e(Context context) {
        return "19";
    }

    @Override // com.google.android.gms.internal.ads.N4
    public final String f(Context context, String str, View view, Activity activity) {
        String strM;
        C2039f5 c2039f5 = this.j;
        if (c2039f5 != null && c2039f5.d) {
            c2039f5.b = System.currentTimeMillis();
        }
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.M2)).booleanValue()) {
            J j = this.k;
            j.h = j.g;
            j.g = SystemClock.uptimeMillis();
        }
        l();
        com.quizlet.data.repository.explanations.exercise.b bVarA = this.d.a();
        if (bVarA == null) {
            return "";
        }
        long jCurrentTimeMillis = System.currentTimeMillis();
        synchronized (bVarA) {
            androidx.compose.ui.node.V v = (androidx.compose.ui.node.V) bVarA.c;
            HashMap mapM = v.m();
            ViewOnAttachStateChangeListenerC1952d5 viewOnAttachStateChangeListenerC1952d5 = (ViewOnAttachStateChangeListenerC1952d5) v.d;
            if (viewOnAttachStateChangeListenerC1952d5.l <= -2) {
                WeakReference weakReference = viewOnAttachStateChangeListenerC1952d5.h;
                if ((weakReference != null ? (View) weakReference.get() : null) == null) {
                    viewOnAttachStateChangeListenerC1952d5.l = -3L;
                }
            }
            mapM.put("lts", Long.valueOf(viewOnAttachStateChangeListenerC1952d5.l));
            mapM.put("f", "c");
            mapM.put("ctx", context);
            mapM.put("cs", str);
            mapM.put("aid", null);
            mapM.put("view", view);
            mapM.put("act", activity);
            strM = com.quizlet.data.repository.explanations.exercise.b.m(bVarA.n(mapM));
        }
        this.f.u(5000, System.currentTimeMillis() - jCurrentTimeMillis, null, strM, null);
        return strM;
    }

    @Override // com.google.android.gms.internal.ads.N4
    public final void g(int i, int i2, int i3) {
        DisplayMetrics displayMetrics;
        if (!((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.Wb)).booleanValue() || (displayMetrics = this.a.getResources().getDisplayMetrics()) == null) {
            return;
        }
        float f = i;
        float f2 = displayMetrics.density;
        float f3 = i2;
        MotionEvent motionEventObtain = MotionEvent.obtain(0L, 0L, 0, f * f2, f3 * f2, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 0, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 0, 0);
        h(motionEventObtain);
        motionEventObtain.recycle();
        float f4 = displayMetrics.density;
        MotionEvent motionEventObtain2 = MotionEvent.obtain(0L, 0L, 2, f * f4, f3 * f4, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 0, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 0, 0);
        h(motionEventObtain2);
        motionEventObtain2.recycle();
        float f5 = displayMetrics.density;
        MotionEvent motionEventObtain3 = MotionEvent.obtain(0L, i3, 1, f * f5, f3 * f5, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 0, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 0, 0);
        h(motionEventObtain3);
        motionEventObtain3.recycle();
    }

    @Override // com.google.android.gms.internal.ads.N4
    public final void h(MotionEvent motionEvent) {
        com.quizlet.data.repository.explanations.exercise.b bVarA = this.d.a();
        if (bVarA != null) {
            try {
                bVarA.i(motionEvent);
            } catch (zzfps e) {
                this.f.r(e.a, -1L, e);
            }
        }
    }

    @Override // com.google.android.gms.internal.ads.N4
    public final String i(Context context, View view, Activity activity) throws IllegalAccessException, IllegalArgumentException, InvocationTargetException {
        String strM;
        C2039f5 c2039f5 = this.j;
        if (c2039f5 != null && c2039f5.d) {
            c2039f5.b = System.currentTimeMillis();
        }
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.M2)).booleanValue()) {
            this.k.b(context, view);
        }
        l();
        com.quizlet.data.repository.explanations.exercise.b bVarA = this.d.a();
        if (bVarA == null) {
            return "";
        }
        long jCurrentTimeMillis = System.currentTimeMillis();
        synchronized (bVarA) {
            androidx.compose.ui.node.V v = (androidx.compose.ui.node.V) bVarA.c;
            HashMap mapM = v.m();
            C2881yn c2881yn = (C2881yn) v.i;
            if (c2881yn != null) {
                List list = (List) c2881yn.b;
                c2881yn.b = Collections.EMPTY_LIST;
                mapM.put("vst", list);
            }
            mapM.put("f", "v");
            mapM.put("ctx", context);
            mapM.put("aid", null);
            mapM.put("view", view);
            mapM.put("act", activity);
            strM = com.quizlet.data.repository.explanations.exercise.b.m(bVarA.n(mapM));
        }
        this.f.u(com.pubmatic.sdk.common.h.REWARD_NOT_SELECTED, System.currentTimeMillis() - jCurrentTimeMillis, null, strM, null);
        return strM;
    }

    public final synchronized void k() {
        long jCurrentTimeMillis = System.currentTimeMillis();
        C1608n c1608nN = n();
        if (c1608nN == null) {
            this.f.s(4013, System.currentTimeMillis() - jCurrentTimeMillis);
        } else if (this.d.b(c1608nN)) {
            this.p = true;
            this.i.countDown();
        }
    }

    public final void l() {
        C1608n c1608n;
        if (this.o) {
            return;
        }
        synchronized (this.n) {
            try {
                if (!this.o) {
                    if ((System.currentTimeMillis() / 1000) - this.m < 3600) {
                        return;
                    }
                    Cs cs = this.d;
                    synchronized (cs.e) {
                        com.quizlet.data.repository.explanations.exercise.b bVar = cs.d;
                        c1608n = bVar != null ? (C1608n) bVar.b : null;
                    }
                    if (c1608n == null || ((C2728v5) c1608n.a).x() - (System.currentTimeMillis() / 1000) < 3600) {
                        int i = this.q - 1;
                        if (i == 2 || i == 4 || i == 5 || i == 6 || i == 7) {
                            this.g.execute(new RunnableC1989e(this, 2));
                        }
                    }
                }
            } catch (Throwable th) {
                throw th;
            } finally {
            }
        }
    }

    public final C1608n n() {
        int i = this.q - 1;
        if (i == 2 || i == 4 || i == 5 || i == 6 || i == 7) {
            if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.u2)).booleanValue()) {
                Bs bs = this.c;
                long jCurrentTimeMillis = System.currentTimeMillis();
                synchronized (Bs.f) {
                    try {
                        C2728v5 c2728v5H = bs.h(1);
                        if (c2728v5H == null) {
                            bs.g(4022, jCurrentTimeMillis);
                            return null;
                        }
                        File fileE = bs.e(c2728v5H.E());
                        File file = new File(fileE, "pcam.jar");
                        if (!file.exists()) {
                            file = new File(fileE, "pcam");
                        }
                        File file2 = new File(fileE, "pcbc");
                        File file3 = new File(fileE, "pcopt");
                        bs.g(5016, jCurrentTimeMillis);
                        return new C1608n(c2728v5H, file, file2, file3);
                    } catch (Throwable th) {
                        throw th;
                    }
                }
            }
            As as = this.b;
            C2728v5 c2728v5D = as.d(1);
            if (c2728v5D != null) {
                String strE = c2728v5D.E();
                File fileQ = AbstractC2025es.q(strE, "pcam.jar", as.f());
                if (!fileQ.exists()) {
                    fileQ = AbstractC2025es.q(strE, "pcam", as.f());
                }
                return new C1608n(c2728v5D, fileQ, AbstractC2025es.q(strE, "pcbc", as.f()), AbstractC2025es.q(strE, "pcopt", as.f()));
            }
        }
        return null;
    }
}
