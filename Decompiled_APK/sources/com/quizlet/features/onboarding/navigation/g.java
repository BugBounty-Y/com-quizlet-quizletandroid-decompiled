package com.quizlet.features.onboarding.navigation;

/* loaded from: classes3.dex */
public final class g extends k {
    public final boolean a;
    public final int b;

    public g(boolean z, int i) {
        this.a = z;
        this.b = i;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof g)) {
            return false;
        }
        g gVar = (g) obj;
        return this.a == gVar.a && this.b == gVar.b;
    }

    public final int hashCode() {
        return Integer.hashCode(this.b) + (Boolean.hashCode(this.a) * 31);
    }

    public final String toString() {
        return "Finish(hasNewHomeData=" + this.a + ", userUpgradeType=" + this.b + ")";
    }
}
