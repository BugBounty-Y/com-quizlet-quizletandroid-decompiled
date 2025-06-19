package com.google.android.gms.internal.fido;

import java.util.Arrays;

/* loaded from: classes2.dex */
public final class a0 extends b0 {
    public final String a;

    public a0(String str) {
        this.a = str;
    }

    @Override // com.google.android.gms.internal.fido.b0
    public final int a() {
        return b0.d((byte) 96);
    }

    @Override // java.lang.Comparable
    public final /* bridge */ /* synthetic */ int compareTo(Object obj) {
        b0 b0Var = (b0) obj;
        int iA = b0Var.a();
        int iD = b0.d((byte) 96);
        if (iD != iA) {
            return iD - b0Var.a();
        }
        String str = ((a0) b0Var).a;
        int length = str.length();
        String str2 = this.a;
        if (str2.length() == length) {
            return str2.compareTo(str);
        }
        return str2.length() - str.length();
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj != null && a0.class == obj.getClass()) {
            return this.a.equals(((a0) obj).a);
        }
        return false;
    }

    public final int hashCode() {
        return Arrays.hashCode(new Object[]{Integer.valueOf(b0.d((byte) 96)), this.a});
    }

    public final String toString() {
        return android.support.v4.media.session.a.t(new StringBuilder("\""), this.a, "\"");
    }
}
