package androidx.compose.ui.platform;

/* renamed from: androidx.compose.ui.platform.d, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0936d extends androidx.appcompat.app.y {
    public static C0936d d;

    @Override // androidx.appcompat.app.y
    public final int[] e(int i) {
        int length = l().length();
        if (length <= 0 || i >= length) {
            return null;
        }
        if (i < 0) {
            i = 0;
        }
        while (i < length && l().charAt(i) == '\n' && (l().charAt(i) == '\n' || (i != 0 && l().charAt(i - 1) != '\n'))) {
            i++;
        }
        if (i >= length) {
            return null;
        }
        int i2 = i + 1;
        while (i2 < length && !v(i2)) {
            i2++;
        }
        return i(i, i2);
    }

    @Override // androidx.appcompat.app.y
    public final int[] o(int i) {
        int length = l().length();
        if (length <= 0 || i <= 0) {
            return null;
        }
        if (i > length) {
            i = length;
        }
        while (i > 0 && l().charAt(i - 1) == '\n' && !v(i)) {
            i--;
        }
        if (i <= 0) {
            return null;
        }
        int i2 = i - 1;
        while (i2 > 0 && (l().charAt(i2) == '\n' || (i2 != 0 && l().charAt(i2 - 1) != '\n'))) {
            i2--;
        }
        return i(i2, i);
    }

    public final boolean v(int i) {
        if (i <= 0 || l().charAt(i - 1) == '\n') {
            return false;
        }
        return i == l().length() || l().charAt(i) == '\n';
    }
}
