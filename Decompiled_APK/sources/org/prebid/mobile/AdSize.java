package org.prebid.mobile;

/* loaded from: classes3.dex */
public class AdSize {
    public int a;
    public int b;

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj != null && getClass() == obj.getClass()) {
            AdSize adSize = (AdSize) obj;
            if (this.a == adSize.a && this.b == adSize.b) {
                return true;
            }
        }
        return false;
    }

    public final int hashCode() {
        return (this.a + "x" + this.b).hashCode();
    }
}
