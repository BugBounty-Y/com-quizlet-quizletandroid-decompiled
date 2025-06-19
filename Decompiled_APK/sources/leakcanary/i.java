package leakcanary;

import android.os.Looper;
import androidx.compose.foundation.C0473q;
import kotlin.jvm.internal.F;

/* loaded from: classes3.dex */
public final class i implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ C0473q b;

    public /* synthetic */ i(C0473q c0473q, int i) {
        this.a = i;
        this.b = c0473q;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                Looper.myQueue().addIdleHandler(new h(this));
                break;
            default:
                ((F) this.b.c).a = true;
                break;
        }
    }
}
