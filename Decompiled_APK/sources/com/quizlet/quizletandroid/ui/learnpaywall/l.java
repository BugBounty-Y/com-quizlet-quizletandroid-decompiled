package com.quizlet.quizletandroid.ui.learnpaywall;

/* loaded from: classes3.dex */
public final class l {
    public final boolean a;
    public final boolean b;

    public l(boolean z, boolean z2) {
        this.a = z;
        this.b = z2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof l)) {
            return false;
        }
        l lVar = (l) obj;
        return this.a == lVar.a && this.b == lVar.b;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.b) + (Boolean.hashCode(this.a) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("PaywallUpgradeSuccess(isPlus=");
        sb.append(this.a);
        sb.append(", fromResults=");
        return android.support.v4.media.session.a.o(")", sb, this.b);
    }
}
