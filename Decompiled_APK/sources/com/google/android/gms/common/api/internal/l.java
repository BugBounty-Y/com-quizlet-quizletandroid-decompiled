package com.google.android.gms.common.api.internal;

import android.app.Activity;
import android.app.PendingIntent;
import android.content.DialogInterface;
import android.os.Bundle;
import android.os.Looper;
import androidx.collection.C0209g;
import com.google.android.gms.common.ConnectionResult;
import com.google.android.gms.common.GoogleApiAvailability;
import com.google.android.gms.internal.ads.Ls;
import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes2.dex */
public final class l implements DialogInterface.OnCancelListener {
    public final Object a;
    public volatile boolean b;
    public final GoogleApiAvailability e;
    public final C1647e g;
    public final AtomicReference c = new AtomicReference(null);
    public final Ls d = new Ls(Looper.getMainLooper(), 1);
    public final C0209g f = new C0209g(0);

    public l(InterfaceC1649g interfaceC1649g, C1647e c1647e, GoogleApiAvailability googleApiAvailability) {
        this.a = interfaceC1649g;
        this.e = googleApiAvailability;
        this.g = c1647e;
        interfaceC1649g.v(this);
    }

    /* JADX WARN: Type inference failed for: r0v0, types: [com.google.android.gms.common.api.internal.g, java.lang.Object] */
    public final Activity a() {
        Activity activityE = this.a.e();
        com.google.android.gms.common.internal.u.h(activityE);
        return activityE;
    }

    public final void b(Bundle bundle) {
        if (bundle != null) {
            this.c.set(bundle.getBoolean("resolving_error", false) ? new D(new ConnectionResult(bundle.getInt("failed_status"), (PendingIntent) bundle.getParcelable("failed_resolution")), bundle.getInt("failed_client_id", -1)) : null);
        }
    }

    public final void c() {
        this.b = false;
        C1647e c1647e = this.g;
        c1647e.getClass();
        synchronized (C1647e.r) {
            try {
                if (c1647e.k == this) {
                    c1647e.k = null;
                    c1647e.l.clear();
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public final void d() {
        if (this.f.isEmpty()) {
            return;
        }
        this.g.e(this);
    }

    @Override // android.content.DialogInterface.OnCancelListener
    public final void onCancel(DialogInterface dialogInterface) {
        ConnectionResult connectionResult = new ConnectionResult(13, null);
        AtomicReference atomicReference = this.c;
        D d = (D) atomicReference.get();
        int i = d == null ? -1 : d.a;
        atomicReference.set(null);
        this.g.h(connectionResult, i);
    }
}
