package androidx.camera.core;

/* loaded from: classes.dex */
public final /* synthetic */ class c0 implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ i0 b;
    public final /* synthetic */ C0187j c;

    public /* synthetic */ c0(i0 i0Var, C0187j c0187j, int i) {
        this.a = i;
        this.b = i0Var;
        this.c = c0187j;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                this.b.b(this.c);
                break;
            default:
                this.b.b(this.c);
                break;
        }
    }
}
