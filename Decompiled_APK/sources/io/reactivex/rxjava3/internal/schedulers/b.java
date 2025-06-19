package io.reactivex.rxjava3.internal.schedulers;

/* loaded from: classes3.dex */
public final class b {
    public final int a;
    public final c[] b;
    public long c;

    public b(int i, q qVar) {
        this.a = i;
        this.b = new c[i];
        for (int i2 = 0; i2 < i; i2++) {
            this.b[i2] = new c(qVar);
        }
    }
}
