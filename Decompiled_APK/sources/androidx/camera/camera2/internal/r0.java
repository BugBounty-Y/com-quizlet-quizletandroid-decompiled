package androidx.camera.camera2.internal;

/* loaded from: classes.dex */
public final /* synthetic */ class r0 implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ androidx.camera.core.a0 b;

    public /* synthetic */ r0(androidx.camera.core.a0 a0Var, int i) {
        this.a = i;
        this.b = a0Var;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                this.b.g();
                break;
            case 1:
                this.b.g();
                break;
            default:
                androidx.camera.core.a0 a0Var = this.b;
                if (a0Var != null) {
                    a0Var.g();
                    break;
                }
                break;
        }
    }
}
