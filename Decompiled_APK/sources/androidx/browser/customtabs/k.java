package androidx.browser.customtabs;

import android.app.ActivityOptions;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.media.AudioManager;
import android.media.Spatializer;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.Trace;
import android.text.TextUtils;
import android.util.SparseArray;
import androidx.appcompat.app.Q;
import com.android.billingclient.api.s;
import com.bumptech.glide.Glide;
import com.bumptech.glide.manager.n;
import com.google.android.gms.common.internal.u;
import com.google.android.gms.internal.ads.AbstractC1795We;
import com.google.android.gms.internal.ads.AbstractC2027eu;
import com.google.android.gms.internal.ads.AbstractC2330lu;
import com.google.android.gms.internal.ads.AbstractC2543qs;
import com.google.android.gms.internal.ads.Bu;
import com.google.android.gms.internal.ads.C1862b2;
import com.google.android.gms.internal.ads.C2147hi;
import com.google.android.gms.internal.ads.C2244ju;
import com.google.android.gms.internal.ads.C2683u3;
import com.google.android.gms.internal.ads.Et;
import com.google.android.gms.internal.ads.ExecutorC2769w3;
import com.google.android.gms.internal.ads.InterfaceC2122h0;
import com.google.android.gms.internal.ads.InterfaceC2380n0;
import com.google.android.gms.internal.ads.J9;
import com.google.android.gms.internal.ads.KF;
import com.google.android.gms.internal.ads.LF;
import com.google.android.gms.internal.ads.PF;
import com.google.android.gms.internal.ads.QF;
import com.google.android.gms.internal.ads.RunnableC2104gj;
import com.google.android.gms.internal.ads.RunnableC2793wl;
import com.google.android.gms.internal.ads.SF;
import com.google.android.gms.internal.ads.V3;
import com.google.android.gms.internal.ads.VF;
import com.google.android.gms.internal.ads.W;
import com.google.android.gms.internal.ads.Y3;
import com.google.android.gms.internal.ads.Yo;
import com.google.android.gms.internal.ads.Z1;
import com.google.android.gms.internal.ads.zzaqd;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3359k2;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3485l;
import com.google.android.gms.internal.mlkit_vision_common.C;
import com.google.android.gms.measurement.internal.O;
import com.google.android.gms.tasks.Task;
import com.google.firebase.crashlytics.internal.metadata.q;
import com.google.mlkit.common.sdkinternal.o;
import java.io.File;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.atomic.AtomicMarkableReference;
import java.util.concurrent.atomic.AtomicReference;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;
import okio.x;

/* loaded from: classes.dex */
public final class k implements com.bumptech.glide.util.g, W, SF {
    public static volatile int e = 1;
    public boolean a;
    public final Object b;
    public Object c;
    public Object d;

    public k(Context context, ExecutorService executorService, com.google.android.gms.tasks.m mVar, boolean z) {
        this.b = context;
        this.c = executorService;
        this.d = mVar;
        this.a = z;
    }

    public static k k(Context context, ExecutorService executorService, boolean z) {
        com.google.android.gms.tasks.f fVar = new com.google.android.gms.tasks.f();
        if (z) {
            executorService.execute(new RunnableC2793wl(context, fVar));
        } else {
            executorService.execute(new RunnableC2104gj(fVar, 19));
        }
        return new k(context, executorService, fVar.a, z);
    }

    @Override // com.google.android.gms.internal.ads.SF
    public Bu a(int i, J9 j9, int[] iArr) {
        VF vf = (VF) this.b;
        PF pf = (PF) this.c;
        KF kf = new KF(vf, pf);
        int i2 = ((int[]) this.d)[i];
        C2244ju c2244ju = AbstractC2330lu.b;
        AbstractC2543qs.g(4, "initialCapacity");
        Object[] objArrCopyOf = new Object[4];
        int i3 = 0;
        int i4 = 0;
        while (i3 < j9.a) {
            int i5 = i;
            J9 j92 = j9;
            LF lf = new LF(i5, j92, i3, pf, iArr[i3], this.a, kf);
            int length = objArrCopyOf.length;
            int i6 = i4 + 1;
            int iH = AbstractC2027eu.h(length, i6);
            if (iH > length) {
                objArrCopyOf = Arrays.copyOf(objArrCopyOf, iH);
            }
            objArrCopyOf[i4] = lf;
            i3++;
            i4 = i6;
            i = i5;
            j9 = j92;
        }
        return AbstractC2330lu.m(i4, objArrCopyOf);
    }

    public void b() {
        com.bumptech.glide.disklrucache.c.a((com.bumptech.glide.disklrucache.c) this.d, this, false);
    }

    public androidx.work.impl.model.c c() {
        Intent intent = (Intent) this.b;
        if (!intent.hasExtra("android.support.customtabs.extra.SESSION")) {
            Bundle bundle = new Bundle();
            bundle.putBinder("android.support.customtabs.extra.SESSION", null);
            intent.putExtras(bundle);
        }
        intent.putExtra("android.support.customtabs.extra.EXTRA_ENABLE_INSTANT_APPS", this.a);
        Integer num = (Integer) ((Q) this.c).a;
        Bundle bundle2 = new Bundle();
        if (num != null) {
            bundle2.putInt("android.support.customtabs.extra.TOOLBAR_COLOR", num.intValue());
        }
        intent.putExtras(bundle2);
        intent.putExtra("androidx.browser.customtabs.extra.SHARE_STATE", 0);
        int i = Build.VERSION.SDK_INT;
        String strA = i.a();
        if (!TextUtils.isEmpty(strA)) {
            Bundle bundleExtra = intent.hasExtra("com.android.browser.headers") ? intent.getBundleExtra("com.android.browser.headers") : new Bundle();
            if (!bundleExtra.containsKey("Accept-Language")) {
                bundleExtra.putString("Accept-Language", strA);
                intent.putExtra("com.android.browser.headers", bundleExtra);
            }
        }
        if (i >= 34) {
            if (((ActivityOptions) this.d) == null) {
                this.d = h.a();
            }
            j.a((ActivityOptions) this.d, false);
        }
        ActivityOptions activityOptions = (ActivityOptions) this.d;
        return new androidx.work.impl.model.c(1, intent, activityOptions != null ? activityOptions.toBundle() : null);
    }

    public boolean d(k kVar) {
        return (((org.ccil.cowan.tagsoup.b) kVar.b).e & ((org.ccil.cowan.tagsoup.b) this.b).d) != 0;
    }

    public void e(boolean z) {
        coil3.disk.e eVar = (coil3.disk.e) this.d;
        synchronized (eVar.h) {
            try {
                if (this.a) {
                    throw new IllegalStateException("editor is closed");
                }
                if (Intrinsics.b(((coil3.disk.a) this.b).g, this)) {
                    coil3.disk.e.a(eVar, this, z);
                }
                this.a = true;
                Unit unit = Unit.a;
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public x f(int i) {
        x xVar;
        coil3.disk.e eVar = (coil3.disk.e) this.d;
        synchronized (eVar.h) {
            if (this.a) {
                throw new IllegalStateException("editor is closed");
            }
            ((boolean[]) this.c)[i] = true;
            Object obj = ((coil3.disk.a) this.b).d.get(i);
            AbstractC3485l.b(eVar.q, (x) obj);
            xVar = (x) obj;
        }
        return xVar;
    }

    public File g() {
        File file;
        synchronized (((com.bumptech.glide.disklrucache.c) this.d)) {
            try {
                com.bumptech.glide.disklrucache.b bVar = (com.bumptech.glide.disklrucache.b) this.b;
                if (bVar.f != this) {
                    throw new IllegalStateException();
                }
                if (!bVar.e) {
                    ((boolean[]) this.c)[0] = true;
                }
                file = bVar.d[0];
                ((com.bumptech.glide.disklrucache.c) this.d).a.mkdirs();
            } catch (Throwable th) {
                throw th;
            }
        }
        return file;
    }

    @Override // com.bumptech.glide.util.g
    public Object get() {
        if (this.a) {
            throw new IllegalStateException("Recursive Registry initialization! In your AppGlideModule and LibraryGlideModules, Make sure you're using the provided Registry rather calling glide.getRegistry()!");
        }
        Trace.beginSection(AbstractC3359k2.f("Glide registry"));
        this.a = true;
        try {
            return com.bumptech.glide.i.a((Glide) this.b, (List) this.c, (C) this.d);
        } finally {
            this.a = false;
            Trace.endSection();
        }
    }

    public int[] h() {
        synchronized (this) {
            try {
                if (!this.a) {
                    return null;
                }
                long[] jArr = (long[]) this.b;
                int length = jArr.length;
                int i = 0;
                int i2 = 0;
                while (i < length) {
                    int i3 = i2 + 1;
                    int i4 = 1;
                    boolean z = jArr[i] > 0;
                    boolean[] zArr = (boolean[]) this.c;
                    if (z != zArr[i2]) {
                        int[] iArr = (int[]) this.d;
                        if (!z) {
                            i4 = 2;
                        }
                        iArr[i2] = i4;
                    } else {
                        ((int[]) this.d)[i2] = 0;
                    }
                    zArr[i2] = z;
                    i++;
                    i2 = i3;
                }
                this.a = false;
                return (int[]) ((int[]) this.d).clone();
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public boolean i(String str, String str2) {
        synchronized (this) {
            try {
                if (!((com.google.firebase.crashlytics.internal.metadata.e) ((AtomicMarkableReference) this.b).getReference()).b(str, str2)) {
                    return false;
                }
                AtomicMarkableReference atomicMarkableReference = (AtomicMarkableReference) this.b;
                atomicMarkableReference.set((com.google.firebase.crashlytics.internal.metadata.e) atomicMarkableReference.getReference(), true);
                q qVar = new q(this, 0);
                AtomicReference atomicReference = (AtomicReference) this.c;
                while (!atomicReference.compareAndSet(null, qVar)) {
                    if (atomicReference.get() != null) {
                        return true;
                    }
                }
                ((com.google.firebase.crashlytics.internal.concurrency.d) ((com.onetrust.otpublishers.headless.UI.TVUI.datautils.d) this.d).c).b.a(qVar);
                return true;
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public void j(Runnable runnable, Executor executor) {
        synchronized (this.b) {
            try {
                if (this.a) {
                    ((ArrayDeque) this.c).add(new o(runnable, executor));
                } else {
                    this.a = true;
                    t(runnable, executor);
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public String l() {
        if (!this.a) {
            this.a = true;
            this.c = ((O) this.d).X().getString((String) this.b, null);
        }
        return (String) this.c;
    }

    public void m(String str) {
        SharedPreferences.Editor editorEdit = ((O) this.d).X().edit();
        editorEdit.putString((String) this.b, str);
        editorEdit.apply();
        this.c = str;
    }

    @Override // com.google.android.gms.internal.ads.W
    public void n() {
        ((W) this.b).n();
        if (!this.a) {
            return;
        }
        int i = 0;
        while (true) {
            SparseArray sparseArray = (SparseArray) this.d;
            if (i >= sparseArray.size()) {
                return;
            }
            ((C1862b2) sparseArray.valueAt(i)).i = true;
            i++;
        }
    }

    public void o() {
        synchronized (this.b) {
            try {
                if (((ArrayDeque) this.c).isEmpty()) {
                    this.a = false;
                    return;
                }
                o oVar = (o) ((ArrayDeque) this.c).remove();
                t(oVar.b, oVar.a);
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    @Override // com.google.android.gms.internal.ads.W
    public void p(InterfaceC2122h0 interfaceC2122h0) {
        ((W) this.b).p(interfaceC2122h0);
    }

    @Override // com.google.android.gms.internal.ads.W
    public InterfaceC2380n0 q(int i, int i2) {
        W w = (W) this.b;
        if (i2 != 3) {
            this.a = true;
            return w.q(i, i2);
        }
        SparseArray sparseArray = (SparseArray) this.d;
        C1862b2 c1862b2 = (C1862b2) sparseArray.get(i);
        if (c1862b2 != null) {
            return c1862b2;
        }
        C1862b2 c1862b22 = new C1862b2(w.q(i, 3), (Z1) this.c);
        sparseArray.put(i, c1862b22);
        return c1862b22;
    }

    public void r(int i, long j, Exception exc) {
        u(i, j, exc, null, null);
    }

    public void s(int i, long j) {
        u(i, j, null, null, null);
    }

    public void t(Runnable runnable, Executor executor) {
        try {
            executor.execute(new com.google.android.gms.tasks.k(this, false, runnable, 4));
        } catch (RejectedExecutionException unused) {
            o();
        }
    }

    public Task u(int i, long j, Exception exc, String str, String str2) {
        if (!this.a) {
            return ((com.google.android.gms.tasks.m) this.d).e((ExecutorService) this.c, new C2147hi(28, (byte) 0));
        }
        Context context = (Context) this.b;
        V3 v3W = Y3.w();
        String packageName = context.getPackageName();
        v3W.e();
        Y3.x((Y3) v3W.b, packageName);
        v3W.e();
        Y3.B((Y3) v3W.b, j);
        int i2 = e;
        v3W.e();
        Y3.D((Y3) v3W.b, i2);
        if (exc != null) {
            Object obj = Et.a;
            StringWriter stringWriter = new StringWriter();
            exc.printStackTrace(new PrintWriter(stringWriter));
            String string = stringWriter.toString();
            v3W.e();
            Y3.C((Y3) v3W.b, string);
            String name = exc.getClass().getName();
            v3W.e();
            Y3.A((Y3) v3W.b, name);
        }
        if (str2 != null) {
            v3W.e();
            Y3.y((Y3) v3W.b, str2);
        }
        if (str != null) {
            v3W.e();
            Y3.z((Y3) v3W.b, str);
        }
        return ((com.google.android.gms.tasks.m) this.d).e((ExecutorService) this.c, new s(v3W, i, 18));
    }

    public k(zzaqd zzaqdVar) {
        this.a = false;
        this.b = null;
        this.c = null;
        this.d = zzaqdVar;
    }

    public /* synthetic */ k(VF vf, PF pf, boolean z, int[] iArr) {
        this.b = vf;
        this.c = pf;
        this.a = z;
        this.d = iArr;
    }

    public k(Object obj, C2683u3 c2683u3) {
        this.a = false;
        this.b = obj;
        this.c = c2683u3;
        this.d = null;
    }

    public k(W w, Z1 z1) {
        this.b = w;
        this.c = z1;
        this.d = new SparseArray();
    }

    public k(O o, String str) {
        this.d = o;
        u.e(str);
        this.b = str;
    }

    public k(Context context, VF vf) {
        AudioManager audioManagerS = context == null ? null : AbstractC1795We.s(context);
        if (audioManagerS != null && !Yo.e(context)) {
            Spatializer spatializer = audioManagerS.getSpatializer();
            this.b = spatializer;
            this.a = spatializer.getImmersiveAudioLevel() != 0;
            QF qf = new QF(vf);
            this.d = qf;
            Looper looperMyLooper = Looper.myLooper();
            AbstractC1795We.p(looperMyLooper);
            Handler handler = new Handler(looperMyLooper);
            this.c = handler;
            spatializer.addOnSpatializerStateChangedListener(new ExecutorC2769w3(handler, 2), qf);
            return;
        }
        this.b = null;
        this.a = false;
        this.c = null;
        this.d = null;
    }

    public k(org.ccil.cowan.tagsoup.b bVar, boolean z) {
        this.b = bVar;
        if (z) {
            org.ccil.cowan.tagsoup.a aVar = bVar.g;
            org.ccil.cowan.tagsoup.a aVar2 = new org.ccil.cowan.tagsoup.a();
            if (aVar2.b != null) {
                for (int i = 0; i < aVar2.a * 5; i++) {
                    aVar2.b[i] = null;
                }
            }
            aVar2.a = 0;
            int length = aVar.getLength();
            aVar2.a = length;
            if (length > 0) {
                aVar2.b = new String[length * 5];
                for (int i2 = 0; i2 < aVar2.a; i2++) {
                    int i3 = i2 * 5;
                    aVar2.b[i3] = aVar.getURI(i2);
                    aVar2.b[i3 + 1] = aVar.getLocalName(i2);
                    aVar2.b[i3 + 2] = aVar.getQName(i2);
                    aVar2.b[i3 + 3] = aVar.getType(i2);
                    aVar2.b[i3 + 4] = aVar.getValue(i2);
                }
            }
            this.c = aVar2;
        } else {
            this.c = new org.ccil.cowan.tagsoup.a();
        }
        this.d = null;
        this.a = false;
    }

    public k(Glide glide, List list, C c) {
        this.b = glide;
        this.c = list;
        this.d = c;
    }

    public k(com.bumptech.glide.load.engine.k kVar, n nVar) {
        this.d = new androidx.work.impl.constraints.d(this, 2);
        this.c = kVar;
        this.b = nVar;
    }

    public k(com.onetrust.otpublishers.headless.UI.TVUI.datautils.d dVar, boolean z) {
        this.d = dVar;
        this.c = new AtomicReference(null);
        this.a = z;
        this.b = new AtomicMarkableReference(new com.google.firebase.crashlytics.internal.metadata.e(z ? 8192 : 1024), false);
    }

    public k(int i, boolean z) {
        switch (i) {
            case 1:
                this.b = new Object();
                this.c = new ArrayList();
                this.d = new ArrayList();
                this.a = true;
                break;
            case 14:
                this.b = new Object();
                this.c = new ArrayDeque();
                this.d = new AtomicReference();
                break;
            default:
                this.b = new Intent("android.intent.action.VIEW");
                this.c = new Q();
                this.a = true;
                break;
        }
    }

    public k(int i) {
        this.b = new long[i];
        this.c = new boolean[i];
        this.d = new int[i];
    }

    public k(androidx.work.impl.model.n nVar) {
        Intent intent = new Intent("android.intent.action.VIEW");
        this.b = intent;
        this.c = new Q();
        this.a = true;
        if (nVar != null) {
            intent.setPackage(((ComponentName) nVar.d).getPackageName());
            g gVar = (g) nVar.c;
            Bundle bundle = new Bundle();
            bundle.putBinder("android.support.customtabs.extra.SESSION", gVar);
            intent.putExtras(bundle);
        }
    }

    public k(coil3.disk.e eVar, coil3.disk.a aVar) {
        this.d = eVar;
        this.b = aVar;
        eVar.getClass();
        this.c = new boolean[2];
    }

    public k(com.bumptech.glide.disklrucache.c cVar, com.bumptech.glide.disklrucache.b bVar) {
        this.d = cVar;
        this.b = bVar;
        this.c = bVar.e ? null : new boolean[cVar.g];
    }
}
