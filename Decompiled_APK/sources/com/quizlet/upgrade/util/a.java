package com.quizlet.upgrade.util;

/* loaded from: classes3.dex */
public final class a {
    public final boolean a;
    public final int b;
    public final boolean c;

    public a(boolean z, int i) {
        this.a = z;
        this.b = i;
        this.c = i != 0;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        a aVar = (a) obj;
        return this.a == aVar.a && this.b == aVar.b;
    }

    public final int hashCode() {
        return Integer.hashCode(this.b) + (Boolean.hashCode(this.a) * 31);
    }

    public final String toString() {
        return "UpgradeActivityResultData(isSuccessful=" + this.a + ", userUpgradeType=" + this.b + ")";
    }
}
