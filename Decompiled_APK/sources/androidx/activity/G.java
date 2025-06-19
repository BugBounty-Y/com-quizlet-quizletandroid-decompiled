package androidx.activity;

import android.window.OnBackInvokedCallback;

/* loaded from: classes.dex */
public final /* synthetic */ class G implements OnBackInvokedCallback {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ G(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    public final void onBackInvoked() {
        switch (this.a) {
            case 0:
                ((F) this.b).invoke();
                break;
            case 1:
                ((androidx.appcompat.app.B) this.b).E();
                break;
            case 2:
                ((Runnable) this.b).run();
                break;
            default:
                ((com.google.android.material.motion.b) this.b).c();
                break;
        }
    }
}
