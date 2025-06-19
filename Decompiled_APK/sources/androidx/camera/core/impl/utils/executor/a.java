package androidx.camera.core.impl.utils.executor;

import com.bumptech.glide.util.m;
import java.util.concurrent.Executor;

/* loaded from: classes.dex */
public final class a implements Executor {
    public static volatile a b;
    public final /* synthetic */ int a;

    @Override // java.util.concurrent.Executor
    public final void execute(Runnable runnable) {
        switch (this.a) {
            case 0:
                runnable.run();
                break;
            case 1:
                new Thread(runnable).start();
                break;
            case 2:
                runnable.run();
                break;
            case 3:
                m.f().post(runnable);
                break;
            case 4:
                runnable.run();
                break;
            case 5:
                runnable.run();
                break;
            default:
                runnable.run();
                break;
        }
    }
}
