package com.google.android.gms.internal.ads;

/* renamed from: com.google.android.gms.internal.ads.yq, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2884yq implements InterfaceC2798wq {
    public final String a;

    public C2884yq(String str) {
        this.a = str;
    }

    public final boolean equals(Object obj) {
        if (obj instanceof C2884yq) {
            return this.a.equals(((C2884yq) obj).a);
        }
        return false;
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return this.a;
    }
}
