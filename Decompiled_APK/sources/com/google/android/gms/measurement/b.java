package com.google.android.gms.measurement;

import android.os.Bundle;
import com.google.android.gms.measurement.internal.E0;
import com.google.android.gms.measurement.internal.InterfaceC3885o0;
import com.google.android.gms.measurement.internal.InterfaceC3887p0;
import java.util.List;
import java.util.Map;

/* loaded from: classes2.dex */
public final class b extends c {
    public final E0 a;

    public b(E0 e0) {
        this.a = e0;
    }

    @Override // com.google.android.gms.measurement.internal.E0
    public final void a(InterfaceC3887p0 interfaceC3887p0) {
        this.a.a(interfaceC3887p0);
    }

    @Override // com.google.android.gms.measurement.internal.E0
    public final List b(String str, String str2) {
        return this.a.b(str, str2);
    }

    @Override // com.google.android.gms.measurement.internal.E0
    public final Map c(String str, String str2, boolean z) {
        return this.a.c(str, str2, z);
    }

    @Override // com.google.android.gms.measurement.internal.E0
    public final void c0(String str) {
        this.a.c0(str);
    }

    @Override // com.google.android.gms.measurement.internal.E0
    public final void d(String str, String str2, Bundle bundle, long j) {
        this.a.d(str, str2, bundle, j);
    }

    @Override // com.google.android.gms.measurement.internal.E0
    public final void e(Bundle bundle) {
        this.a.e(bundle);
    }

    @Override // com.google.android.gms.measurement.internal.E0
    public final void f(String str, String str2, Bundle bundle) {
        this.a.f(str, str2, bundle);
    }

    @Override // com.google.android.gms.measurement.internal.E0
    public final String g() {
        return this.a.g();
    }

    @Override // com.google.android.gms.measurement.internal.E0
    public final void h(String str) {
        this.a.h(str);
    }

    @Override // com.google.android.gms.measurement.internal.E0
    public final String i() {
        return this.a.i();
    }

    @Override // com.google.android.gms.measurement.internal.E0
    public final void j(String str, String str2, Bundle bundle) {
        this.a.j(str, str2, bundle);
    }

    @Override // com.google.android.gms.measurement.internal.E0
    public final void k(InterfaceC3885o0 interfaceC3885o0) {
        this.a.k(interfaceC3885o0);
    }

    @Override // com.google.android.gms.measurement.c
    public final Map l() {
        return this.a.c(null, null, true);
    }

    @Override // com.google.android.gms.measurement.internal.E0
    public final String n() {
        return this.a.n();
    }

    @Override // com.google.android.gms.measurement.internal.E0
    public final int zza(String str) {
        return this.a.zza(str);
    }

    @Override // com.google.android.gms.measurement.internal.E0
    public final long zzb() {
        return this.a.zzb();
    }

    @Override // com.google.android.gms.measurement.internal.E0
    public final String zzi() {
        return this.a.zzi();
    }
}
