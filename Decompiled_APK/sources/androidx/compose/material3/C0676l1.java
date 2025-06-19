package androidx.compose.material3;

import android.view.View;

/* renamed from: androidx.compose.material3.l1, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0676l1 {
    public int a;
    public int b;

    public /* synthetic */ C0676l1(int i, int i2, boolean z) {
        this.a = i;
        this.b = i2;
    }

    public int a(int i) {
        int i2 = this.b;
        if (i2 == 0) {
            return i < this.a ? -1 : 0;
        }
        int i3 = this.a;
        if (i >= i3) {
            return (i - i3) / (i2 + 1);
        }
        return -1;
    }

    public void b(androidx.recyclerview.widget.F0 f0) {
        View view = f0.itemView;
        this.a = view.getLeft();
        this.b = view.getTop();
        view.getRight();
        view.getBottom();
    }

    public int c() {
        int i = this.b;
        if (i == 2) {
            return 10;
        }
        if (i == 5) {
            return 11;
        }
        if (i == 29) {
            return 12;
        }
        if (i == 42) {
            return 16;
        }
        if (i != 22) {
            return i != 23 ? 0 : 15;
        }
        return 1073741824;
    }

    public C0676l1(int i, int i2) {
        int i3 = (i2 & 2) != 0 ? i : 10;
        this.a = i;
        this.b = i3;
    }
}
