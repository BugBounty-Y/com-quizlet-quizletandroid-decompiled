package com.google.android.gms.internal.measurement;

import com.google.android.gms.internal.ads.C1721Kc;
import java.util.ArrayList;
import java.util.Iterator;

/* renamed from: com.google.android.gms.internal.measurement.f, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2987f implements InterfaceC3027n {
    public final InterfaceC3027n a;
    public final String b;

    public C2987f(String str) {
        this.a = InterfaceC3027n.Q0;
        this.b = str;
    }

    @Override // com.google.android.gms.internal.measurement.InterfaceC3027n
    public final InterfaceC3027n c(String str, C1721Kc c1721Kc, ArrayList arrayList) {
        throw new IllegalStateException("Control does not have functions");
    }

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof C2987f)) {
            return false;
        }
        C2987f c2987f = (C2987f) obj;
        return this.b.equals(c2987f.b) && this.a.equals(c2987f.a);
    }

    @Override // com.google.android.gms.internal.measurement.InterfaceC3027n
    public final Double g() {
        throw new IllegalStateException("Control is not a double");
    }

    @Override // com.google.android.gms.internal.measurement.InterfaceC3027n
    public final Boolean h() {
        throw new IllegalStateException("Control is not a boolean");
    }

    public final int hashCode() {
        return this.a.hashCode() + (this.b.hashCode() * 31);
    }

    @Override // com.google.android.gms.internal.measurement.InterfaceC3027n
    public final InterfaceC3027n j() {
        return new C2987f(this.b, this.a.j());
    }

    @Override // com.google.android.gms.internal.measurement.InterfaceC3027n
    public final Iterator k() {
        return null;
    }

    @Override // com.google.android.gms.internal.measurement.InterfaceC3027n
    public final String zzi() {
        throw new IllegalStateException("Control is not a String");
    }

    public C2987f(String str, InterfaceC3027n interfaceC3027n) {
        this.a = interfaceC3027n;
        this.b = str;
    }
}
