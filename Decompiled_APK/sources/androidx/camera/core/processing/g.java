package androidx.camera.core.processing;

/* loaded from: classes.dex */
public final /* synthetic */ class g implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ j b;

    public /* synthetic */ g(j jVar, int i) {
        this.a = i;
        this.b = jVar;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                this.b.a();
                break;
            case 1:
                this.b.b();
                break;
            default:
                j jVar = this.b;
                l lVar = jVar.r;
                if (lVar != null) {
                    lVar.f();
                }
                if (jVar.q == null) {
                    jVar.p.c();
                    break;
                }
                break;
        }
    }
}
