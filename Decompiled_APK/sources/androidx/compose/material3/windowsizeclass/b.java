package androidx.compose.material3.windowsizeclass;

import java.util.Set;

/* loaded from: classes.dex */
public final class b {
    public final int a;
    public final int b;

    public b(int i, int i2) {
        this.a = i;
        this.b = i2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj != null && b.class == obj.getClass()) {
            b bVar = (b) obj;
            Set set = c.b;
            if (this.a == bVar.a) {
                Set set2 = a.b;
                if (this.b == bVar.b) {
                    return true;
                }
            }
        }
        return false;
    }

    public final int hashCode() {
        Set set = c.b;
        int iHashCode = Integer.hashCode(this.a) * 31;
        Set set2 = a.b;
        return Integer.hashCode(this.b) + iHashCode;
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("WindowSizeClass(");
        Set set = c.b;
        String str = "";
        int i = this.a;
        sb.append((Object) "WindowWidthSizeClass.".concat(i == 0 ? "Compact" : i == 1 ? "Medium" : i == 2 ? "Expanded" : ""));
        sb.append(", ");
        Set set2 = a.b;
        int i2 = this.b;
        if (i2 == 0) {
            str = "Compact";
        } else if (i2 == 1) {
            str = "Medium";
        } else if (i2 == 2) {
            str = "Expanded";
        }
        sb.append((Object) "WindowHeightSizeClass.".concat(str));
        sb.append(')');
        return sb.toString();
    }
}
