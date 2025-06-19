package androidx.camera.camera2.internal;

import android.content.Context;
import android.content.IntentFilter;
import android.hardware.camera2.CaptureRequest;
import android.hardware.camera2.TotalCaptureResult;
import android.os.Binder;
import android.os.Build;
import android.os.Looper;
import android.os.Parcel;
import android.view.View;
import android.view.ViewGroup;
import com.facebook.internal.C1549d;
import com.google.android.gms.common.ConnectionResult;
import com.google.android.gms.common.internal.InterfaceC1652b;
import com.google.android.gms.common.internal.InterfaceC1653c;
import com.google.android.gms.internal.ads.AbstractC2773w7;
import com.google.android.gms.internal.ads.AbstractC2857y5;
import com.google.android.gms.internal.ads.C2601s7;
import com.google.android.gms.internal.ads.C2800ws;
import com.google.android.gms.internal.ads.C2886ys;
import com.google.android.gms.internal.ads.C2929zs;
import com.google.android.gms.internal.ads.zzfpa;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.WeakHashMap;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class m0 implements InterfaceC1652b, InterfaceC1653c {
    public boolean a;
    public boolean b;
    public final Object c;
    public final Object d;
    public Object e;

    public m0(int i) {
        switch (i) {
            case 4:
                this.c = new HashMap();
                this.d = new HashSet();
                break;
            default:
                this.a = false;
                this.d = new WeakHashMap();
                this.c = new C1549d(this, 5);
                break;
        }
    }

    @Override // com.google.android.gms.common.internal.InterfaceC1652b
    public void V(int i) {
    }

    @Override // com.google.android.gms.common.internal.InterfaceC1652b
    public void X() {
        synchronized (this.e) {
            try {
                if (this.b) {
                    return;
                }
                this.b = true;
                try {
                    C2929zs c2929zs = (C2929zs) ((C2886ys) this.c).m();
                    zzfpa zzfpaVar = new zzfpa(1, ((C2800ws) this.d).d());
                    Parcel parcelF3 = c2929zs.f3();
                    AbstractC2857y5.c(parcelF3, zzfpaVar);
                    c2929zs.d4(2, parcelF3);
                } catch (Exception unused) {
                } catch (Throwable th) {
                    g();
                    throw th;
                }
                g();
            } catch (Throwable th2) {
                throw th2;
            }
        }
    }

    public boolean a(com.google.android.material.internal.i iVar) {
        int id = iVar.getId();
        HashSet hashSet = (HashSet) this.d;
        if (hashSet.contains(Integer.valueOf(id))) {
            return false;
        }
        com.google.android.material.internal.i iVar2 = (com.google.android.material.internal.i) ((HashMap) this.c).get(Integer.valueOf(c()));
        if (iVar2 != null) {
            e(iVar2, false);
        }
        boolean zAdd = hashSet.add(Integer.valueOf(id));
        if (!iVar.isChecked()) {
            iVar.setChecked(true);
        }
        return zAdd;
    }

    public ArrayList b(ViewGroup viewGroup) {
        HashSet hashSet = new HashSet((HashSet) this.d);
        ArrayList arrayList = new ArrayList();
        for (int i = 0; i < viewGroup.getChildCount(); i++) {
            View childAt = viewGroup.getChildAt(i);
            if ((childAt instanceof com.google.android.material.internal.i) && hashSet.contains(Integer.valueOf(childAt.getId()))) {
                arrayList.add(Integer.valueOf(childAt.getId()));
            }
        }
        return arrayList;
    }

    public int c() {
        if (!this.a) {
            return -1;
        }
        HashSet hashSet = (HashSet) this.d;
        if (hashSet.isEmpty()) {
            return -1;
        }
        return ((Integer) hashSet.iterator().next()).intValue();
    }

    public void d() {
        androidx.webkit.internal.p pVar = (androidx.webkit.internal.p) this.e;
        if (pVar != null) {
            new HashSet((HashSet) this.d);
            com.google.android.material.chip.j jVar = (com.google.android.material.chip.j) pVar.b;
            com.google.android.material.chip.i iVar = jVar.g;
            if (iVar != null) {
                jVar.h.b(jVar);
                com.google.android.material.chip.j jVar2 = (com.google.android.material.chip.j) ((com.airbnb.lottie.network.c) iVar).b;
                if (jVar2.h.a) {
                    jVar2.getCheckedChipId();
                    throw null;
                }
            }
        }
    }

    public boolean e(com.google.android.material.internal.i iVar, boolean z) {
        int id = iVar.getId();
        HashSet hashSet = (HashSet) this.d;
        if (!hashSet.contains(Integer.valueOf(id))) {
            return false;
        }
        if (z && hashSet.size() == 1 && hashSet.contains(Integer.valueOf(id))) {
            iVar.setChecked(true);
            return false;
        }
        boolean zRemove = hashSet.remove(Integer.valueOf(id));
        if (iVar.isChecked()) {
            iVar.setChecked(false);
        }
        return zRemove;
    }

    public synchronized void f(Context context) {
        try {
            if (this.a) {
                return;
            }
            Context applicationContext = context.getApplicationContext();
            this.e = applicationContext;
            if (applicationContext == null) {
                this.e = context;
            }
            AbstractC2773w7.a((Context) this.e);
            C2601s7 c2601s7 = AbstractC2773w7.V3;
            com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
            this.b = ((Boolean) rVar.c.a(c2601s7)).booleanValue();
            IntentFilter intentFilter = new IntentFilter();
            intentFilter.addAction("android.intent.action.SCREEN_ON");
            intentFilter.addAction("android.intent.action.SCREEN_OFF");
            intentFilter.addAction("android.intent.action.USER_PRESENT");
            if (!((Boolean) rVar.c.a(AbstractC2773w7.Ya)).booleanValue() || Build.VERSION.SDK_INT < 33) {
                ((Context) this.e).registerReceiver((C1549d) this.c, intentFilter);
            } else {
                ((Context) this.e).registerReceiver((C1549d) this.c, intentFilter, 4);
            }
            this.a = true;
        } catch (Throwable th) {
            throw th;
        }
    }

    @Override // com.google.android.gms.common.internal.InterfaceC1653c
    public void f0(ConnectionResult connectionResult) {
    }

    public void g() {
        synchronized (this.e) {
            try {
                C2886ys c2886ys = (C2886ys) this.c;
                if (c2886ys.q() || c2886ys.r()) {
                    c2886ys.e();
                }
                Binder.flushPendingCommands();
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public synchronized void h(Context context, C1549d c1549d) {
        if (this.b) {
            ((WeakHashMap) this.d).remove(c1549d);
        } else {
            context.unregisterReceiver(c1549d);
        }
    }

    public m0(Context context, Looper looper, C2800ws c2800ws) {
        this.e = new Object();
        this.a = false;
        this.b = false;
        this.d = c2800ws;
        this.c = new C2886ys(12800000, context, looper, this, this);
    }

    public m0(C0137n c0137n, androidx.camera.camera2.internal.compat.k kVar, androidx.camera.core.impl.utils.executor.k kVar2) {
        this.c = c0137n;
        com.google.android.gms.common.wrappers.a.e(new C0132i(kVar, 1));
        this.d = new androidx.lifecycle.Y(0);
        c0137n.h(new InterfaceC0136m() { // from class: androidx.camera.camera2.internal.l0
            @Override // androidx.camera.camera2.internal.InterfaceC0136m
            public final boolean d(TotalCaptureResult totalCaptureResult) {
                m0 m0Var = this.a;
                if (((androidx.concurrent.futures.i) m0Var.e) != null) {
                    Integer num = (Integer) totalCaptureResult.getRequest().get(CaptureRequest.FLASH_MODE);
                    if ((num != null && num.intValue() == 2) == m0Var.b) {
                        ((androidx.concurrent.futures.i) m0Var.e).b(null);
                        m0Var.e = null;
                    }
                }
                return false;
            }
        });
    }

    public m0(Context context, String str, androidx.sqlite.db.b callback, boolean z, boolean z2) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(callback, "callback");
        this.c = context;
        this.d = str;
        this.e = callback;
        this.a = z;
        this.b = z2;
    }
}
