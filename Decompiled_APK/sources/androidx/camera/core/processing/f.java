package androidx.camera.core.processing;

import com.google.android.gms.internal.mlkit_vision_barcode.T;

/* loaded from: classes.dex */
public final /* synthetic */ class f implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ k b;

    public /* synthetic */ f(k kVar, int i) {
        this.a = i;
        this.b = kVar;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                k kVar = this.b;
                kVar.getClass();
                T.e().execute(new f(kVar, 1));
                break;
            default:
                k kVar2 = this.b;
                if (!kVar2.n) {
                    kVar2.d();
                    break;
                }
                break;
        }
    }
}
