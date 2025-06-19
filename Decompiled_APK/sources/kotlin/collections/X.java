package kotlin.collections;

/* loaded from: classes3.dex */
public final class X extends AbstractC4912c {
    public int c;
    public int d;
    public final /* synthetic */ Y e;

    public X(Y y) {
        this.e = y;
        this.c = y.e;
        this.d = y.d;
    }

    @Override // kotlin.collections.AbstractC4912c
    public final void a() {
        int i = this.c;
        if (i == 0) {
            this.a = 2;
            return;
        }
        Y y = this.e;
        int i2 = this.d;
        this.b = y.b[i2];
        this.a = 1;
        this.d = (i2 + 1) % y.c;
        this.c = i - 1;
    }
}
