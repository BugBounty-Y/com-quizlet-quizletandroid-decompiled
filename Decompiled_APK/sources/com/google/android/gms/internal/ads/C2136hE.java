package com.google.android.gms.internal.ads;

/* renamed from: com.google.android.gms.internal.ads.hE, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2136hE {
    public static final C2136hE d = new androidx.camera.camera2.internal.compat.workaround.c().c();
    public final boolean a;
    public final boolean b;
    public final boolean c;

    public /* synthetic */ C2136hE(androidx.camera.camera2.internal.compat.workaround.c cVar) {
        this.a = cVar.a;
        this.b = cVar.b;
        this.c = cVar.c;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || C2136hE.class != obj.getClass()) {
            return false;
        }
        C2136hE c2136hE = (C2136hE) obj;
        return this.a == c2136hE.a && this.b == c2136hE.b && this.c == c2136hE.c;
    }

    public final int hashCode() {
        int i = (this.a ? 1 : 0) << 2;
        boolean z = this.b;
        return (z ? 1 : 0) + (z ? 1 : 0) + i + (this.c ? 1 : 0);
    }
}
