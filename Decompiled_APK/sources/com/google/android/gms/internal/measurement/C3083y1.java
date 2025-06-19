package com.google.android.gms.internal.measurement;

import android.app.Activity;
import android.app.Application;
import android.content.Context;
import android.hardware.camera2.CameraCharacteristics;
import android.net.Uri;
import android.os.Parcel;
import android.os.RemoteException;
import android.text.TextUtils;
import android.util.Log;
import androidx.camera.core.C0196t;
import androidx.camera.core.internal.compat.quirk.IncorrectJpegMetadataQuirk;
import androidx.camera.core.internal.compat.quirk.LowMemoryQuirk;
import com.google.android.gms.internal.ads.AbstractC2773w7;
import com.google.android.gms.internal.ads.C1708Ib;
import com.google.android.gms.internal.ads.C2584rr;
import com.google.android.gms.internal.ads.InterfaceC1720Kb;
import com.google.android.gms.internal.ads.K5;
import com.google.android.gms.internal.ads.L5;
import com.google.android.gms.internal.ads.Pq;
import com.google.android.gms.internal.ads.Pv;
import com.google.android.gms.internal.ads.Tq;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3242q6;
import com.google.android.gms.internal.mlkit_vision_barcode.C7;
import com.google.android.gms.internal.mlkit_vision_barcode.x7;
import com.google.android.gms.tasks.Task;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.WeakHashMap;
import java.util.concurrent.Executor;

/* renamed from: com.google.android.gms.internal.measurement.y1, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3083y1 implements Pv, io.reactivex.rxjava3.core.q {
    public static C3083y1 e;
    public final /* synthetic */ int a;
    public boolean b;
    public final Object c;
    public Object d;

    public C3083y1(int i) {
        this.a = i;
        switch (i) {
            case 4:
                this.c = Collections.newSetFromMap(new WeakHashMap());
                this.d = new HashSet();
                break;
            case 5:
            case 7:
            default:
                this.b = false;
                this.c = null;
                this.d = null;
                break;
            case 6:
                this.c = new Object();
                this.d = null;
                this.b = false;
                break;
            case 8:
                this.c = new Object();
                break;
        }
    }

    public static boolean d(C0196t c0196t, C0196t c0196t2) {
        AbstractC3242q6.h("Fully specified range is not actually fully specified.", c0196t2.b());
        int i = c0196t.a;
        int i2 = c0196t2.a;
        if (i == 2 && i2 == 1) {
            return false;
        }
        if (i != 2 && i != 0 && i != i2) {
            return false;
        }
        int i3 = c0196t.b;
        return i3 == 0 || i3 == c0196t2.b;
    }

    public static boolean e(C0196t c0196t, C0196t c0196t2, HashSet hashSet) {
        if (hashSet.contains(c0196t2)) {
            return d(c0196t, c0196t2);
        }
        c0196t.toString();
        c0196t2.toString();
        AbstractC3053s1.f(3, "DynamicRangeResolver");
        return false;
    }

    public static C0196t g(C0196t c0196t, LinkedHashSet linkedHashSet, HashSet hashSet) {
        if (c0196t.a == 1) {
            return null;
        }
        Iterator it2 = linkedHashSet.iterator();
        while (it2.hasNext()) {
            C0196t c0196t2 = (C0196t) it2.next();
            AbstractC3242q6.g(c0196t2, "Fully specified DynamicRange cannot be null.");
            AbstractC3242q6.h("Fully specified DynamicRange must have fully defined encoding.", c0196t2.b());
            if (c0196t2.a != 1 && e(c0196t, c0196t2, hashSet)) {
                return c0196t2;
            }
        }
        return null;
    }

    public static void h(HashSet hashSet, C0196t c0196t, com.google.firebase.platforminfo.c cVar) {
        AbstractC3242q6.h("Cannot update already-empty constraints.", !hashSet.isEmpty());
        Set setC = ((androidx.camera.camera2.internal.compat.params.b) cVar.a).c(c0196t);
        if (setC.isEmpty()) {
            return;
        }
        HashSet hashSet2 = new HashSet(hashSet);
        hashSet.retainAll(setC);
        if (hashSet.isEmpty()) {
            throw new IllegalArgumentException("Constraints of dynamic range cannot be combined with existing constraints.\nDynamic range:\n  " + c0196t + "\nConstraints:\n  " + TextUtils.join("\n  ", setC) + "\nExisting constraints:\n  " + TextUtils.join("\n  ", hashSet2));
        }
    }

    public static C3083y1 i(Context context) {
        C3083y1 c3083y1;
        synchronized (C3083y1.class) {
            try {
                if (e == null) {
                    e = androidx.core.content.c.b(context, "com.google.android.providers.gsf.permission.READ_GSERVICES") == 0 ? new C3083y1(context) : new C3083y1(0);
                }
                C3083y1 c3083y12 = e;
                if (c3083y12 != null && ((C3078x1) c3083y12.d) != null && !c3083y12.b) {
                    try {
                        context.getContentResolver().registerContentObserver(AbstractC3048r1.a, true, (C3078x1) e.d);
                        C3083y1 c3083y13 = e;
                        c3083y13.getClass();
                        c3083y13.b = true;
                    } catch (SecurityException e2) {
                        Log.e("GservicesLoader", "Unable to register Gservices content observer", e2);
                    }
                }
                c3083y1 = e;
                c3083y1.getClass();
            } catch (Throwable th) {
                throw th;
            }
        }
        return c3083y1;
    }

    @Override // io.reactivex.rxjava3.core.q
    public void a(io.reactivex.rxjava3.disposables.b bVar) {
        io.reactivex.rxjava3.core.q qVar = (io.reactivex.rxjava3.core.q) this.c;
        try {
            ((io.reactivex.rxjava3.functions.d) this.d).accept(bVar);
            qVar.a(bVar);
        } catch (Throwable th) {
            x7.b(th);
            this.b = true;
            bVar.dispose();
            qVar.a(io.reactivex.rxjava3.internal.disposables.b.a);
            qVar.onError(th);
        }
    }

    public boolean b(long j) {
        Object obj;
        ArrayList arrayList = (ArrayList) ((com.quizlet.data.repository.qclass.c) this.d).b;
        int size = arrayList.size();
        int i = 0;
        while (true) {
            if (i >= size) {
                obj = null;
                break;
            }
            obj = arrayList.get(i);
            if (androidx.compose.ui.input.pointer.m.a(((androidx.compose.ui.input.pointer.p) obj).a, j)) {
                break;
            }
            i++;
        }
        androidx.compose.ui.input.pointer.p pVar = (androidx.compose.ui.input.pointer.p) obj;
        if (pVar != null) {
            return pVar.h;
        }
        return false;
    }

    @Override // com.google.android.gms.internal.ads.Pv
    /* renamed from: c */
    public void mo15c(Object obj) {
        switch (this.a) {
            case 5:
                List<Uri> list = (List) obj;
                try {
                    com.google.android.gms.ads.nonagon.signalgeneration.i iVar = (com.google.android.gms.ads.nonagon.signalgeneration.i) this.d;
                    Iterator it2 = list.iterator();
                    while (true) {
                        if (it2.hasNext()) {
                            if (com.google.android.gms.ads.nonagon.signalgeneration.i.k4((Uri) it2.next(), iVar.x, iVar.y)) {
                                iVar.t.getAndIncrement();
                            }
                        }
                    }
                    C1708Ib c1708Ib = (C1708Ib) ((InterfaceC1720Kb) this.c);
                    Parcel parcelF3 = c1708Ib.f3();
                    parcelF3.writeTypedList(list);
                    c1708Ib.d4(1, parcelF3);
                    if (!iVar.o && !this.b) {
                    }
                    for (Uri uri : list) {
                        boolean zK4 = com.google.android.gms.ads.nonagon.signalgeneration.i.k4(uri, iVar.x, iVar.y);
                        C2584rr c2584rr = iVar.m;
                        if (zK4) {
                            c2584rr.a(com.google.android.gms.ads.nonagon.signalgeneration.i.m4(uri, iVar.w, "1").toString(), null, null, null);
                        } else {
                            if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.t7)).booleanValue()) {
                                c2584rr.a(uri.toString(), null, null, null);
                            }
                        }
                    }
                    break;
                } catch (RemoteException e2) {
                    com.google.android.gms.ads.internal.util.client.i.f("", e2);
                    return;
                }
                break;
            default:
                Pq pq = (Pq) this.d;
                pq.h(true);
                Tq tq = (Tq) this.c;
                tq.a(pq);
                if (this.b) {
                    tq.h();
                    break;
                }
                break;
        }
    }

    public boolean f(com.bumptech.glide.request.c cVar) {
        boolean z = true;
        if (cVar == null) {
            return true;
        }
        boolean zRemove = ((Set) this.c).remove(cVar);
        if (!((HashSet) this.d).remove(cVar) && !zRemove) {
            z = false;
        }
        if (z) {
            cVar.clear();
        }
        return z;
    }

    public void j(com.google.android.gms.tasks.l lVar) {
        synchronized (this.c) {
            try {
                if (((ArrayDeque) this.d) == null) {
                    this.d = new ArrayDeque();
                }
                ((ArrayDeque) this.d).add(lVar);
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public void k(Task task) {
        com.google.android.gms.tasks.l lVar;
        synchronized (this.c) {
            if (((ArrayDeque) this.d) != null && !this.b) {
                this.b = true;
                while (true) {
                    synchronized (this.c) {
                        try {
                            lVar = (com.google.android.gms.tasks.l) ((ArrayDeque) this.d).poll();
                            if (lVar == null) {
                                this.b = false;
                                return;
                            }
                        } finally {
                        }
                    }
                    lVar.a(task);
                }
            }
        }
    }

    public void l(L5 l5) {
        synchronized (this.c) {
            try {
                if (((K5) this.d) == null) {
                    this.d = new K5();
                }
                K5 k5 = (K5) this.d;
                synchronized (k5.c) {
                    k5.f.add(l5);
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:28:0x0042, code lost:
    
        r6 = true;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.String m(java.lang.String r9) {
        /*
            r8 = this;
            java.lang.Object r0 = r8.c
            android.content.Context r0 = (android.content.Context) r0
            r1 = 0
            if (r0 == 0) goto L8f
            boolean r2 = com.google.android.gms.internal.measurement.AbstractC3058t1.b
            r3 = 1
            if (r2 == 0) goto Ld
            goto L5b
        Ld:
            java.lang.Class<com.google.android.gms.internal.measurement.t1> r2 = com.google.android.gms.internal.measurement.AbstractC3058t1.class
            monitor-enter(r2)
            boolean r4 = com.google.android.gms.internal.measurement.AbstractC3058t1.b     // Catch: java.lang.Throwable -> L16
            if (r4 == 0) goto L19
            monitor-exit(r2)     // Catch: java.lang.Throwable -> L16
            goto L5b
        L16:
            r9 = move-exception
            goto L8d
        L19:
            r4 = r3
        L1a:
            r5 = 2
            r6 = 0
            if (r4 > r5) goto L51
            android.os.UserManager r5 = com.google.android.gms.internal.measurement.AbstractC3058t1.a     // Catch: java.lang.Throwable -> L16
            if (r5 != 0) goto L2c
            java.lang.Class<android.os.UserManager> r5 = android.os.UserManager.class
            java.lang.Object r5 = r0.getSystemService(r5)     // Catch: java.lang.Throwable -> L16
            android.os.UserManager r5 = (android.os.UserManager) r5     // Catch: java.lang.Throwable -> L16
            com.google.android.gms.internal.measurement.AbstractC3058t1.a = r5     // Catch: java.lang.Throwable -> L16
        L2c:
            android.os.UserManager r5 = com.google.android.gms.internal.measurement.AbstractC3058t1.a     // Catch: java.lang.Throwable -> L16
            if (r5 != 0) goto L32
            r6 = r3
            goto L55
        L32:
            boolean r7 = r5.isUserUnlocked()     // Catch: java.lang.Throwable -> L16 java.lang.NullPointerException -> L44
            if (r7 != 0) goto L42
            android.os.UserHandle r7 = android.os.Process.myUserHandle()     // Catch: java.lang.Throwable -> L16 java.lang.NullPointerException -> L44
            boolean r0 = r5.isUserRunning(r7)     // Catch: java.lang.Throwable -> L16 java.lang.NullPointerException -> L44
            if (r0 != 0) goto L51
        L42:
            r6 = r3
            goto L51
        L44:
            r5 = move-exception
            java.lang.String r6 = "DirectBootUtils"
            java.lang.String r7 = "Failed to check if user is unlocked."
            android.util.Log.w(r6, r7, r5)     // Catch: java.lang.Throwable -> L16
            com.google.android.gms.internal.measurement.AbstractC3058t1.a = r1     // Catch: java.lang.Throwable -> L16
            int r4 = r4 + 1
            goto L1a
        L51:
            if (r6 == 0) goto L55
            com.google.android.gms.internal.measurement.AbstractC3058t1.a = r1     // Catch: java.lang.Throwable -> L16
        L55:
            if (r6 == 0) goto L59
            com.google.android.gms.internal.measurement.AbstractC3058t1.b = r3     // Catch: java.lang.Throwable -> L16
        L59:
            monitor-exit(r2)     // Catch: java.lang.Throwable -> L16
            r3 = r6
        L5b:
            if (r3 != 0) goto L5e
            goto L8f
        L5e:
            com.google.android.gms.internal.measurement.t r0 = new com.google.android.gms.internal.measurement.t     // Catch: java.lang.NullPointerException -> L76 java.lang.SecurityException -> L78 java.lang.IllegalStateException -> L7a
            r0.<init>(r8, r9)     // Catch: java.lang.NullPointerException -> L76 java.lang.SecurityException -> L78 java.lang.IllegalStateException -> L7a
            java.lang.Object r0 = r0.b()     // Catch: java.lang.SecurityException -> L68 java.lang.NullPointerException -> L76 java.lang.IllegalStateException -> L7a
            goto L73
        L68:
            long r2 = android.os.Binder.clearCallingIdentity()     // Catch: java.lang.NullPointerException -> L76 java.lang.SecurityException -> L78 java.lang.IllegalStateException -> L7a
            java.lang.Object r0 = r0.b()     // Catch: java.lang.Throwable -> L7c
            android.os.Binder.restoreCallingIdentity(r2)     // Catch: java.lang.NullPointerException -> L76 java.lang.SecurityException -> L78 java.lang.IllegalStateException -> L7a
        L73:
            java.lang.String r0 = (java.lang.String) r0     // Catch: java.lang.NullPointerException -> L76 java.lang.SecurityException -> L78 java.lang.IllegalStateException -> L7a
            return r0
        L76:
            r0 = move-exception
            goto L81
        L78:
            r0 = move-exception
            goto L81
        L7a:
            r0 = move-exception
            goto L81
        L7c:
            r0 = move-exception
            android.os.Binder.restoreCallingIdentity(r2)     // Catch: java.lang.NullPointerException -> L76 java.lang.SecurityException -> L78 java.lang.IllegalStateException -> L7a
            throw r0     // Catch: java.lang.NullPointerException -> L76 java.lang.SecurityException -> L78 java.lang.IllegalStateException -> L7a
        L81:
            java.lang.String r2 = "Unable to read GServices for: "
            java.lang.String r9 = r2.concat(r9)
            java.lang.String r2 = "GservicesLoader"
            android.util.Log.e(r2, r9, r0)
            return r1
        L8d:
            monitor-exit(r2)     // Catch: java.lang.Throwable -> L16
            throw r9
        L8f:
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.measurement.C3083y1.m(java.lang.String):java.lang.String");
    }

    public void n(Context context) {
        synchronized (this.c) {
            try {
                if (!this.b) {
                    Context applicationContext = context.getApplicationContext();
                    if (applicationContext == null) {
                        applicationContext = context;
                    }
                    Application application = applicationContext instanceof Application ? (Application) applicationContext : null;
                    if (application == null) {
                        com.google.android.gms.ads.internal.util.client.i.h("Can not cast Context to Application");
                        return;
                    }
                    if (((K5) this.d) == null) {
                        this.d = new K5();
                    }
                    K5 k5 = (K5) this.d;
                    if (!k5.i) {
                        application.registerActivityLifecycleCallbacks(k5);
                        if (context instanceof Activity) {
                            k5.a((Activity) context);
                        }
                        k5.b = application;
                        k5.j = ((Long) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.X0)).longValue();
                        k5.i = true;
                    }
                    this.b = true;
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public void o(L5 l5) {
        synchronized (this.c) {
            try {
                K5 k5 = (K5) this.d;
                if (k5 == null) {
                    return;
                }
                synchronized (k5.c) {
                    k5.f.remove(l5);
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    @Override // io.reactivex.rxjava3.core.q
    public void onError(Throwable th) {
        if (this.b) {
            C7.c(th);
        } else {
            ((io.reactivex.rxjava3.core.q) this.c).onError(th);
        }
    }

    @Override // io.reactivex.rxjava3.core.q, com.google.android.gms.tasks.d
    public void onSuccess(Object obj) {
        if (this.b) {
            return;
        }
        ((io.reactivex.rxjava3.core.q) this.c).onSuccess(obj);
    }

    public String toString() {
        switch (this.a) {
            case 4:
                StringBuilder sb = new StringBuilder();
                sb.append(super.toString());
                sb.append("{numRequests=");
                sb.append(((Set) this.c).size());
                sb.append(", isPaused=");
                return android.support.v4.media.session.a.o("}", sb, this.b);
            default:
                return super.toString();
        }
    }

    @Override // com.google.android.gms.internal.ads.Pv
    public void zza(Throwable th) {
        switch (this.a) {
            case 5:
                try {
                    InterfaceC1720Kb interfaceC1720Kb = (InterfaceC1720Kb) this.c;
                    String str = "Internal error: " + th.getMessage();
                    C1708Ib c1708Ib = (C1708Ib) interfaceC1720Kb;
                    Parcel parcelF3 = c1708Ib.f3();
                    parcelF3.writeString(str);
                    c1708Ib.d4(2, parcelF3);
                    break;
                } catch (RemoteException e2) {
                    com.google.android.gms.ads.internal.util.client.i.f("", e2);
                    return;
                }
            default:
                Pq pq = (Pq) this.d;
                if (pq.n()) {
                    pq.g(th);
                    pq.h(false);
                    Tq tq = (Tq) this.c;
                    tq.a(pq);
                    if (this.b) {
                        tq.h();
                        break;
                    }
                }
                break;
        }
    }

    public /* synthetic */ C3083y1(int i, Object obj, Object obj2) {
        this.a = i;
        this.c = obj;
        this.d = obj2;
    }

    public C3083y1(com.google.android.gms.ads.nonagon.signalgeneration.i iVar, InterfaceC1720Kb interfaceC1720Kb, boolean z) {
        this.a = 5;
        this.c = interfaceC1720Kb;
        this.b = z;
        this.d = iVar;
    }

    public C3083y1(Tq tq, Pq pq, boolean z) {
        this.a = 7;
        this.c = tq;
        this.d = pq;
        this.b = z;
    }

    public C3083y1(Context context) {
        this.a = 0;
        this.b = false;
        this.c = context;
        this.d = new C3078x1(null);
    }

    public C3083y1(Executor executor) {
        this.a = 2;
        androidx.camera.core.impl.i0 i0Var = androidx.camera.core.internal.compat.quirk.a.a;
        if (androidx.camera.core.internal.compat.quirk.a.a.b(LowMemoryQuirk.class) != null) {
            this.c = new androidx.camera.core.impl.utils.executor.k(executor);
        } else {
            this.c = executor;
        }
        this.d = i0Var;
        this.b = i0Var.a(IncorrectJpegMetadataQuirk.class);
    }

    public C3083y1(androidx.camera.camera2.internal.compat.k kVar) {
        this.a = 1;
        this.c = kVar;
        this.d = com.google.firebase.platforminfo.c.m(kVar);
        int[] iArr = (int[]) kVar.a(CameraCharacteristics.REQUEST_AVAILABLE_CAPABILITIES);
        boolean z = false;
        if (iArr != null) {
            int length = iArr.length;
            int i = 0;
            while (true) {
                if (i >= length) {
                    break;
                }
                if (iArr[i] == 18) {
                    z = true;
                    break;
                }
                i++;
            }
        }
        this.b = z;
    }
}
