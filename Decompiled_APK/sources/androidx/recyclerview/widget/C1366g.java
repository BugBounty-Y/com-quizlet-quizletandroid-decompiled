package androidx.recyclerview.widget;

/* renamed from: androidx.recyclerview.widget.g, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1366g {
    public final C1356b a;
    public int b = 0;
    public int c = -1;
    public int d = -1;
    public Object e = null;

    public C1366g(C1356b c1356b) {
        this.a = c1356b;
    }

    public final void a() {
        int i = this.b;
        if (i == 0) {
            return;
        }
        C1356b c1356b = this.a;
        if (i == 1) {
            c1356b.c(this.c, this.d);
        } else if (i == 2) {
            c1356b.d(this.c, this.d);
        } else if (i == 3) {
            ((AbstractC1361d0) c1356b.a).notifyItemRangeChanged(this.c, this.d, this.e);
        }
        this.e = null;
        this.b = 0;
    }

    public final void b(int i, int i2, Object obj) {
        int i3;
        int i4;
        int i5;
        if (this.b == 3 && i <= (i4 = this.d + (i3 = this.c)) && (i5 = i + i2) >= i3 && this.e == obj) {
            this.c = Math.min(i, i3);
            this.d = Math.max(i4, i5) - this.c;
            return;
        }
        a();
        this.c = i;
        this.d = i2;
        this.e = obj;
        this.b = 3;
    }

    public final void c(int i, int i2) {
        a();
        ((AbstractC1361d0) this.a.a).notifyItemMoved(i, i2);
    }
}
