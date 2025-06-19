package com.google.firebase.analytics;

import android.os.BadParcelableException;
import android.os.Bundle;
import android.os.NetworkOnMainThreadException;
import android.os.RemoteException;
import android.util.Log;
import com.google.android.gms.internal.measurement.BinderC2993g0;
import com.google.android.gms.internal.measurement.C2963a0;
import com.google.android.gms.internal.measurement.C2983e0;
import com.google.android.gms.internal.measurement.C3008j0;
import com.google.android.gms.internal.measurement.G;
import com.google.android.gms.internal.measurement.U;
import com.google.android.gms.internal.measurement.V;
import com.google.android.gms.internal.measurement.W;
import com.google.android.gms.measurement.internal.E0;
import com.google.android.gms.measurement.internal.InterfaceC3885o0;
import com.google.android.gms.measurement.internal.InterfaceC3887p0;
import java.util.List;
import java.util.Map;

/* loaded from: classes2.dex */
public final class a implements E0 {
    public final /* synthetic */ C3008j0 a;

    public a(C3008j0 c3008j0) {
        this.a = c3008j0;
    }

    @Override // com.google.android.gms.measurement.internal.E0
    public final void a(InterfaceC3887p0 interfaceC3887p0) {
        this.a.a(interfaceC3887p0);
    }

    @Override // com.google.android.gms.measurement.internal.E0
    public final List b(String str, String str2) {
        return this.a.g(str, str2);
    }

    @Override // com.google.android.gms.measurement.internal.E0
    public final Map c(String str, String str2, boolean z) {
        return this.a.h(str, str2, z);
    }

    @Override // com.google.android.gms.measurement.internal.E0
    public final void c0(String str) {
        C3008j0 c3008j0 = this.a;
        c3008j0.c(new W(c3008j0, str, 2));
    }

    @Override // com.google.android.gms.measurement.internal.E0
    public final void d(String str, String str2, Bundle bundle, long j) {
        Long lValueOf = Long.valueOf(j);
        C3008j0 c3008j0 = this.a;
        c3008j0.c(new C2983e0(c3008j0, lValueOf, str, str2, bundle, true, false));
    }

    @Override // com.google.android.gms.measurement.internal.E0
    public final void e(Bundle bundle) {
        C3008j0 c3008j0 = this.a;
        c3008j0.c(new V(c3008j0, bundle, 0));
    }

    @Override // com.google.android.gms.measurement.internal.E0
    public final void f(String str, String str2, Bundle bundle) {
        C3008j0 c3008j0 = this.a;
        c3008j0.c(new C2983e0(c3008j0, null, str, str2, bundle, true, true));
    }

    @Override // com.google.android.gms.measurement.internal.E0
    public final String g() {
        C3008j0 c3008j0 = this.a;
        G g = new G();
        c3008j0.c(new C2963a0(c3008j0, g, 1));
        return (String) G.f0(String.class, g.X(50L));
    }

    @Override // com.google.android.gms.measurement.internal.E0
    public final void h(String str) {
        C3008j0 c3008j0 = this.a;
        c3008j0.c(new W(c3008j0, str, 1));
    }

    @Override // com.google.android.gms.measurement.internal.E0
    public final String i() {
        C3008j0 c3008j0 = this.a;
        G g = new G();
        c3008j0.c(new C2963a0(c3008j0, g, 3));
        return (String) G.f0(String.class, g.X(500L));
    }

    @Override // com.google.android.gms.measurement.internal.E0
    public final void j(String str, String str2, Bundle bundle) {
        C3008j0 c3008j0 = this.a;
        c3008j0.c(new U(c3008j0, str, str2, bundle, 1));
    }

    @Override // com.google.android.gms.measurement.internal.E0
    public final void k(InterfaceC3885o0 interfaceC3885o0) {
        C3008j0 c3008j0 = this.a;
        BinderC2993g0 binderC2993g0 = new BinderC2993g0(interfaceC3885o0, 0);
        if (c3008j0.i != null) {
            try {
                c3008j0.i.setEventInterceptor(binderC2993g0);
                return;
            } catch (BadParcelableException | NetworkOnMainThreadException | RemoteException | IllegalArgumentException | IllegalStateException | NullPointerException | SecurityException | UnsupportedOperationException unused) {
                Log.w(c3008j0.a, "Failed to set event interceptor on calling thread. Trying again on the dynamite thread.");
            }
        }
        c3008j0.c(new V(c3008j0, binderC2993g0, 3));
    }

    @Override // com.google.android.gms.measurement.internal.E0
    public final String n() {
        C3008j0 c3008j0 = this.a;
        G g = new G();
        c3008j0.c(new C2963a0(c3008j0, g, 0));
        return (String) G.f0(String.class, g.X(500L));
    }

    @Override // com.google.android.gms.measurement.internal.E0
    public final int zza(String str) {
        return this.a.d(str);
    }

    @Override // com.google.android.gms.measurement.internal.E0
    public final long zzb() {
        return this.a.e();
    }

    @Override // com.google.android.gms.measurement.internal.E0
    public final String zzi() {
        C3008j0 c3008j0 = this.a;
        G g = new G();
        c3008j0.c(new C2963a0(c3008j0, g, 4));
        return (String) G.f0(String.class, g.X(500L));
    }
}
