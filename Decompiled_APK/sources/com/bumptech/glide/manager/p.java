package com.bumptech.glide.manager;

import android.content.Context;
import android.media.Image;
import android.media.ImageReader;
import android.net.ConnectivityManager;
import android.net.Uri;
import android.os.Binder;
import android.os.Parcel;
import android.os.RemoteException;
import android.util.Log;
import android.view.Surface;
import androidx.camera.core.C0149a;
import androidx.camera.core.O;
import androidx.camera.core.impl.Q;
import androidx.camera.core.impl.S;
import androidx.collection.I;
import androidx.paging.R0;
import com.google.android.gms.ads.internal.client.r;
import com.google.android.gms.ads.internal.client.zze;
import com.google.android.gms.internal.ads.AbstractC2773w7;
import com.google.android.gms.internal.ads.C1668Bd;
import com.google.android.gms.internal.ads.C1708Ib;
import com.google.android.gms.internal.ads.C1820a4;
import com.google.android.gms.internal.ads.C1924ce;
import com.google.android.gms.internal.ads.C2143he;
import com.google.android.gms.internal.ads.C2172i6;
import com.google.android.gms.internal.ads.C2313ld;
import com.google.android.gms.internal.ads.C2584rr;
import com.google.android.gms.internal.ads.C2880ym;
import com.google.android.gms.internal.ads.Fw;
import com.google.android.gms.internal.ads.InterfaceC1720Kb;
import com.google.android.gms.internal.ads.InterfaceC2589rw;
import com.google.android.gms.internal.ads.Pv;
import com.google.android.gms.internal.ads.Px;
import com.google.android.gms.internal.ads.T3;
import com.google.android.gms.internal.ads.Z3;
import com.google.android.gms.internal.ads.zzedj;
import com.google.android.gms.internal.mlkit_vision_camera.D1;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.CancellationException;
import java.util.concurrent.Executor;
import java.util.concurrent.locks.ReentrantLock;
import kotlin.collections.C;
import kotlin.collections.G;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.E;
import kotlinx.coroutines.y0;

/* loaded from: classes.dex */
public final class p implements S, Pv, InterfaceC2589rw, io.reactivex.rxjava3.functions.h {
    public static volatile p d;
    public boolean a;
    public Object b;
    public final Object c;

    public p(com.google.android.gms.ads.nonagon.signalgeneration.i iVar, InterfaceC1720Kb interfaceC1720Kb, boolean z) {
        this.b = interfaceC1720Kb;
        this.a = z;
        this.c = iVar;
    }

    public static final void a(p pVar) {
        ((I) pVar.b).a();
        int i = 0;
        pVar.a = false;
        androidx.compose.runtime.collection.b bVar = (androidx.compose.runtime.collection.b) pVar.c;
        int i2 = bVar.c;
        if (i2 > 0) {
            Object[] objArr = bVar.a;
            do {
                ((Function0) objArr[i]).invoke();
                i++;
            } while (i < i2);
        }
        bVar.i();
    }

    /* JADX WARN: Removed duplicated region for block: B:18:0x005e  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void d(com.bumptech.glide.manager.p r15) {
        /*
            java.lang.Object r0 = r15.b
            androidx.collection.I r0 = (androidx.collection.I) r0
            java.lang.Object[] r1 = r0.b
            long[] r2 = r0.a
            int r3 = r2.length
            int r3 = r3 + (-2)
            r4 = 0
            if (r3 < 0) goto L63
            r5 = r4
        Lf:
            r6 = r2[r5]
            long r8 = ~r6
            r10 = 7
            long r8 = r8 << r10
            long r8 = r8 & r6
            r10 = -9187201950435737472(0x8080808080808080, double:-2.937446524422997E-306)
            long r8 = r8 & r10
            int r8 = (r8 > r10 ? 1 : (r8 == r10 ? 0 : -1))
            if (r8 == 0) goto L5e
            int r8 = r5 - r3
            int r8 = ~r8
            int r8 = r8 >>> 31
            r9 = 8
            int r8 = 8 - r8
            r10 = r4
        L29:
            if (r10 >= r8) goto L5c
            r11 = 255(0xff, double:1.26E-321)
            long r11 = r11 & r6
            r13 = 128(0x80, double:6.3E-322)
            int r11 = (r11 > r13 ? 1 : (r11 == r13 ? 0 : -1))
            if (r11 >= 0) goto L58
            int r11 = r5 << 3
            int r11 = r11 + r10
            r11 = r1[r11]
            androidx.compose.ui.focus.t r11 = (androidx.compose.ui.focus.t) r11
            r11.getClass()
            com.bumptech.glide.manager.p r12 = androidx.compose.ui.focus.a.I(r11)
            java.lang.Object r12 = r12.b
            androidx.collection.I r12 = (androidx.collection.I) r12
            java.lang.Object r12 = r12.f(r11)
            androidx.compose.ui.focus.s r12 = (androidx.compose.ui.focus.s) r12
            if (r12 == 0) goto L51
            r11.p = r12
            goto L58
        L51:
            java.lang.String r15 = "committing a node that was not updated in the current transaction"
            com.google.android.gms.internal.mlkit_vision_barcode.W4.g(r15)
            r15 = 0
            throw r15
        L58:
            long r6 = r6 >> r9
            int r10 = r10 + 1
            goto L29
        L5c:
            if (r8 != r9) goto L63
        L5e:
            if (r5 == r3) goto L63
            int r5 = r5 + 1
            goto Lf
        L63:
            r0.a()
            r15.a = r4
            java.lang.Object r15 = r15.c
            androidx.compose.runtime.collection.b r15 = (androidx.compose.runtime.collection.b) r15
            r15.i()
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.bumptech.glide.manager.p.d(com.bumptech.glide.manager.p):void");
    }

    public static p f(Context context) {
        if (d == null) {
            synchronized (p.class) {
                try {
                    if (d == null) {
                        d = new p(context.getApplicationContext(), 0);
                    }
                } finally {
                }
            }
        }
        return d;
    }

    public static /* bridge */ /* synthetic */ void i(p pVar) {
        synchronized (pVar.c) {
            try {
                C2172i6 c2172i6 = (C2172i6) pVar.b;
                if (c2172i6 == null) {
                    return;
                }
                c2172i6.e();
                pVar.b = null;
                Binder.flushPendingCommands();
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    @Override // androidx.camera.core.impl.S
    public int C() {
        int maxImages;
        synchronized (this.c) {
            maxImages = ((ImageReader) this.b).getMaxImages();
        }
        return maxImages;
    }

    @Override // androidx.camera.core.impl.S
    public O F() {
        Image imageAcquireNextImage;
        synchronized (this.c) {
            try {
                imageAcquireNextImage = ((ImageReader) this.b).acquireNextImage();
            } catch (RuntimeException e) {
                if (!"ImageReaderContext is not initialized".equals(e.getMessage())) {
                    throw e;
                }
                imageAcquireNextImage = null;
            }
            if (imageAcquireNextImage == null) {
                return null;
            }
            return new C0149a(imageAcquireNextImage);
        }
    }

    @Override // androidx.camera.core.impl.S
    public void G(final Q q, final Executor executor) {
        synchronized (this.c) {
            this.a = false;
            ((ImageReader) this.b).setOnImageAvailableListener(new ImageReader.OnImageAvailableListener() { // from class: androidx.camera.core.b
                @Override // android.media.ImageReader.OnImageAvailableListener
                public final void onImageAvailable(ImageReader imageReader) {
                    com.bumptech.glide.manager.p pVar = this.a;
                    Executor executor2 = executor;
                    androidx.camera.core.impl.Q q2 = q;
                    synchronized (pVar.c) {
                        try {
                            if (!pVar.a) {
                                executor2.execute(new androidx.activity.r(9, pVar, q2));
                            }
                        } catch (Throwable th) {
                            throw th;
                        }
                    }
                }
            }, androidx.camera.core.impl.utils.e.b());
        }
    }

    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        List localClassFolders = (List) obj;
        Intrinsics.checkNotNullParameter(localClassFolders, "localClassFolders");
        com.quizlet.local.ormlite.models.classfolder.b bVar = (com.quizlet.local.ormlite.models.classfolder.b) ((Function1) this.b).invoke(localClassFolders);
        List list = bVar.a;
        com.quizlet.assembly.compose.modals.g gVar = new com.quizlet.assembly.compose.modals.g(this.a, 6);
        com.quizlet.local.ormlite.models.bookmark.a aVar = (com.quizlet.local.ormlite.models.bookmark.a) this.c;
        aVar.getClass();
        com.quizlet.features.settings.composables.dialogs.a transform = new com.quizlet.features.settings.composables.dialogs.a(gVar, 3);
        Intrinsics.checkNotNullParameter(list, "<this>");
        List second = bVar.b;
        Intrinsics.checkNotNullParameter(second, "second");
        Intrinsics.checkNotNullParameter(transform, "transform");
        ArrayList models = new ArrayList();
        for (Object obj2 : list) {
            ArrayList arrayList = new ArrayList(C.q(second, 10));
            Iterator it2 = second.iterator();
            while (it2.hasNext()) {
                arrayList.add(transform.invoke(obj2, it2.next()));
            }
            G.u(models, arrayList);
        }
        Intrinsics.checkNotNullParameter(models, "models");
        return aVar.f(models, true);
    }

    @Override // androidx.camera.core.impl.S
    public int b() {
        int height;
        synchronized (this.c) {
            height = ((ImageReader) this.b).getHeight();
        }
        return height;
    }

    @Override // com.google.android.gms.internal.ads.Pv
    /* renamed from: c */
    public void mo15c(Object obj) {
        ArrayList arrayList = (ArrayList) obj;
        try {
            C1708Ib c1708Ib = (C1708Ib) ((InterfaceC1720Kb) this.b);
            Parcel parcelF3 = c1708Ib.f3();
            parcelF3.writeTypedList(arrayList);
            c1708Ib.d4(1, parcelF3);
            com.google.android.gms.ads.nonagon.signalgeneration.i iVar = (com.google.android.gms.ads.nonagon.signalgeneration.i) this.c;
            if (!iVar.n && !this.a) {
                return;
            }
            Iterator it2 = arrayList.iterator();
            while (it2.hasNext()) {
                Uri uri = (Uri) it2.next();
                boolean zK4 = com.google.android.gms.ads.nonagon.signalgeneration.i.k4(uri, iVar.z, iVar.A);
                C2584rr c2584rr = iVar.m;
                if (zK4) {
                    c2584rr.a(com.google.android.gms.ads.nonagon.signalgeneration.i.m4(uri, iVar.w, "1").toString(), null, null, null);
                } else {
                    if (((Boolean) r.d.c.a(AbstractC2773w7.t7)).booleanValue()) {
                        c2584rr.a(uri.toString(), null, null, null);
                    }
                }
            }
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.i.f("", e);
        }
    }

    @Override // androidx.camera.core.impl.S
    public void close() {
        synchronized (this.c) {
            ((ImageReader) this.b).close();
        }
    }

    public void e() {
        ((kotlinx.coroutines.channels.h) this.b).k(new CancellationException("onBack cancelled"), true);
        ((y0) this.c).j(null);
    }

    public void g() {
        if (this.a || ((HashSet) this.c).isEmpty()) {
            return;
        }
        androidx.browser.customtabs.k kVar = (androidx.browser.customtabs.k) this.b;
        com.bumptech.glide.load.engine.k kVar2 = (com.bumptech.glide.load.engine.k) kVar.c;
        boolean z = false;
        kVar.a = ((ConnectivityManager) kVar2.get()).getActiveNetwork() != null;
        try {
            ((ConnectivityManager) kVar2.get()).registerDefaultNetworkCallback((androidx.work.impl.constraints.d) kVar.d);
            z = true;
        } catch (RuntimeException e) {
            if (Log.isLoggable("ConnectivityMonitor", 5)) {
                Log.w("ConnectivityMonitor", "Failed to register callback", e);
            }
        }
        this.a = z;
    }

    @Override // androidx.camera.core.impl.S
    public int getWidth() {
        int width;
        synchronized (this.c) {
            width = ((ImageReader) this.b).getWidth();
        }
        return width;
    }

    public synchronized void h(int i) {
        if (this.a) {
            return;
        }
        this.a = true;
        j(new zze(i, "Error from: " + ((C2880ym) this.b).a + ", code: " + i, "undefined", null, null));
    }

    public synchronized void j(zze zzeVar) {
        int i = 1;
        if (true == ((Boolean) r.d.c.a(AbstractC2773w7.z5)).booleanValue()) {
            i = 3;
        }
        ((C2313ld) this.c).d(new zzedj(i, zzeVar));
    }

    @Override // androidx.camera.core.impl.S
    public O l() {
        Image imageAcquireLatestImage;
        synchronized (this.c) {
            try {
                imageAcquireLatestImage = ((ImageReader) this.b).acquireLatestImage();
            } catch (RuntimeException e) {
                if (!"ImageReaderContext is not initialized".equals(e.getMessage())) {
                    throw e;
                }
                imageAcquireLatestImage = null;
            }
            if (imageAcquireLatestImage == null) {
                return null;
            }
            return new C0149a(imageAcquireLatestImage);
        }
    }

    @Override // androidx.camera.core.impl.S
    public int m() {
        int imageFormat;
        synchronized (this.c) {
            imageFormat = ((ImageReader) this.b).getImageFormat();
        }
        return imageFormat;
    }

    @Override // androidx.camera.core.impl.S
    public void p() {
        synchronized (this.c) {
            this.a = true;
            ((ImageReader) this.b).setOnImageAvailableListener(null, null);
        }
    }

    @Override // androidx.camera.core.impl.S
    public Surface w() {
        Surface surface;
        synchronized (this.c) {
            surface = ((ImageReader) this.b).getSurface();
        }
        return surface;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2589rw
    /* renamed from: zza */
    public Fw mo22zza() {
        boolean z = this.a;
        C2143he c2143he = (C2143he) this.b;
        C2143he c2143he2 = true != z ? null : c2143he;
        C1668Bd c1668Bd = c2143he.d;
        C1924ce c1924ce = new C1924ce((String) this.c, c2143he2, c1668Bd.d, c1668Bd.e, c1668Bd.h);
        c2143he.t.add(new WeakReference(c1924ce));
        return c1924ce;
    }

    public p(C2880ym c2880ym, C2313ld c2313ld) {
        this.b = c2880ym;
        this.c = c2313ld;
        this.a = false;
    }

    public /* synthetic */ p(Object obj, Object obj2, boolean z) {
        this.b = obj;
        this.c = obj2;
        this.a = z;
    }

    public p(T3 t3) {
        this.b = t3.z();
        this.a = t3.C();
        this.c = t3.x();
        t3.y();
    }

    @Override // com.google.android.gms.internal.ads.Pv
    public void zza(Throwable th) {
        try {
            InterfaceC1720Kb interfaceC1720Kb = (InterfaceC1720Kb) this.b;
            String str = "Internal error: " + th.getMessage();
            C1708Ib c1708Ib = (C1708Ib) interfaceC1720Kb;
            Parcel parcelF3 = c1708Ib.f3();
            parcelF3.writeString(str);
            c1708Ib.d4(2, parcelF3);
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.i.f("", e);
        }
    }

    public p(String str) {
        this.b = str;
        this.a = false;
        this.c = Z3.x();
        int i = C1820a4.zza;
    }

    public p(int i) {
        switch (i) {
            case 4:
                R0 callbackInvoker = R0.a;
                Intrinsics.checkNotNullParameter(callbackInvoker, "callbackInvoker");
                this.b = new ReentrantLock();
                this.c = new ArrayList();
                break;
            case 10:
                this.b = new ArrayList();
                this.c = Px.b;
                this.a = false;
                break;
            default:
                long[] jArr = androidx.collection.S.a;
                this.b = new I();
                this.c = new androidx.compose.runtime.collection.b(new Function0[16]);
                break;
        }
    }

    public p(ImageReader imageReader) {
        this.c = new Object();
        this.a = true;
        this.b = imageReader;
    }

    public p(Context context, int i) {
        switch (i) {
            case 7:
                this.c = new Object();
                break;
            default:
                this.c = new HashSet();
                this.b = new androidx.browser.customtabs.k(new com.bumptech.glide.load.engine.k(new androidx.emoji2.text.m(context, 1)), new n(this));
                break;
        }
    }

    public p(kotlinx.coroutines.C c, boolean z, Function2 function2, androidx.activity.compose.r rVar) {
        this.a = z;
        this.b = D1.a(-2, 4, kotlinx.coroutines.channels.a.a);
        this.c = E.A(c, null, null, new androidx.activity.compose.q(rVar, function2, this, null), 3);
    }
}
