package com.google.android.gms.internal.measurement;

import com.google.android.gms.internal.ads.C1721Kc;
import java.util.ArrayList;
import java.util.Iterator;

/* renamed from: com.google.android.gms.internal.measurement.o, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3032o implements InterfaceC3027n {
    public final String a;
    public final ArrayList b;

    public C3032o(ArrayList arrayList, String str) {
        this.a = str;
        ArrayList arrayList2 = new ArrayList();
        this.b = arrayList2;
        arrayList2.addAll(arrayList);
    }

    @Override // com.google.android.gms.internal.measurement.InterfaceC3027n
    public final InterfaceC3027n c(String str, C1721Kc c1721Kc, ArrayList arrayList) {
        throw new IllegalStateException("Statement is not an evaluated entity");
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C3032o)) {
            return false;
        }
        C3032o c3032o = (C3032o) obj;
        String str = this.a;
        if (str == null ? c3032o.a == null : str.equals(c3032o.a)) {
            return this.b.equals(c3032o.b);
        }
        return false;
    }

    @Override // com.google.android.gms.internal.measurement.InterfaceC3027n
    public final Double g() {
        throw new IllegalStateException("Statement cannot be cast as Double");
    }

    @Override // com.google.android.gms.internal.measurement.InterfaceC3027n
    public final Boolean h() {
        throw new IllegalStateException("Statement cannot be cast as Boolean");
    }

    public final int hashCode() {
        String str = this.a;
        return this.b.hashCode() + ((str != null ? str.hashCode() : 0) * 31);
    }

    @Override // com.google.android.gms.internal.measurement.InterfaceC3027n
    public final InterfaceC3027n j() {
        return this;
    }

    @Override // com.google.android.gms.internal.measurement.InterfaceC3027n
    public final Iterator k() {
        return null;
    }

    @Override // com.google.android.gms.internal.measurement.InterfaceC3027n
    public final String zzi() {
        throw new IllegalStateException("Statement cannot be cast as String");
    }
}
