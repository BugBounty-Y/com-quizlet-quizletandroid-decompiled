package androidx.camera.core;

/* loaded from: classes.dex */
public final /* synthetic */ class e0 implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ j0 b;

    public /* synthetic */ e0(j0 j0Var, int i) {
        this.a = i;
        this.b = j0Var;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                this.b.f.cancel(true);
                break;
            default:
                this.b.c();
                break;
        }
    }
}
