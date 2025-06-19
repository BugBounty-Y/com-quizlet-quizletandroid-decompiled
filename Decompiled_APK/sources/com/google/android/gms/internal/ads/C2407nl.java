package com.google.android.gms.internal.ads;

/* renamed from: com.google.android.gms.internal.ads.nl, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2407nl {
    public final Object a;
    public androidx.appcompat.app.K b = new androidx.appcompat.app.K(10);
    public boolean c;
    public boolean d;

    public C2407nl(Object obj) {
        this.a = obj;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || C2407nl.class != obj.getClass()) {
            return false;
        }
        return this.a.equals(((C2407nl) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }
}
