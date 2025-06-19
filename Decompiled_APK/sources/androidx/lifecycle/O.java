package androidx.lifecycle;

/* loaded from: classes.dex */
public final class O implements Runnable {
    public final /* synthetic */ T a;

    public O(T t) {
        this.a = t;
    }

    @Override // java.lang.Runnable
    public final void run() {
        Object obj;
        synchronized (this.a.a) {
            obj = this.a.f;
            this.a.f = T.k;
        }
        this.a.l(obj);
    }
}
