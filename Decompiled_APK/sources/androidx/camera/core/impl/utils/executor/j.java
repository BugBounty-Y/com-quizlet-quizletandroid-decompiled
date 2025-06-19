package androidx.camera.core.impl.utils.executor;

import android.os.Process;
import com.google.android.gms.internal.mlkit_vision_common.R2;

/* loaded from: classes.dex */
public final class j implements Runnable {
    public final /* synthetic */ int a;
    public final Runnable b;

    public /* synthetic */ j(Runnable runnable, int i) {
        this.a = i;
        this.b = runnable;
    }

    @Override // java.lang.Runnable
    public final void run() throws SecurityException, IllegalArgumentException {
        switch (this.a) {
            case 0:
                this.b.run();
                break;
            case 1:
                Process.setThreadPriority(10);
                this.b.run();
                break;
            case 2:
                try {
                    this.b.run();
                    break;
                } catch (Exception e) {
                    R2.d("Executor", "Background execution failure.", e);
                    return;
                }
            case 3:
                Process.setThreadPriority(0);
                this.b.run();
                break;
            default:
                this.b.run();
                break;
        }
    }

    public String toString() {
        switch (this.a) {
            case 4:
                return this.b.toString();
            default:
                return super.toString();
        }
    }
}
