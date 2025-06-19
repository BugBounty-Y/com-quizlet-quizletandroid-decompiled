package com.quizlet.uicommon.ui.common.util;

/* loaded from: classes3.dex */
public final class b extends d {
    public final boolean a;
    public final boolean b;

    public b(boolean z, boolean z2) {
        this.a = z;
        this.b = z2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof b)) {
            return false;
        }
        b bVar = (b) obj;
        return this.a == bVar.a && this.b == bVar.b;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.b) + (Boolean.hashCode(this.a) * 31);
    }

    public final String toString() {
        return "TakeNewTest(isMetered=" + this.a + ", isPlus=" + this.b + ")";
    }
}
