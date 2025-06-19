package androidx.camera.camera2.internal.compat;

/* loaded from: classes.dex */
public final /* synthetic */ class o implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ p b;
    public final /* synthetic */ String c;

    public /* synthetic */ o(p pVar, String str, int i) {
        this.a = i;
        this.b = pVar;
        this.c = str;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                this.b.b.onCameraAvailable(this.c);
                break;
            default:
                this.b.b.onCameraUnavailable(this.c);
                break;
        }
    }
}
