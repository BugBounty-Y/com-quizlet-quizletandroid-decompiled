package androidx.camera.core;

import java.lang.ref.WeakReference;
import java.util.concurrent.atomic.AtomicBoolean;

/* loaded from: classes.dex */
public final class G extends AbstractC0199w {
    public final /* synthetic */ int d = 1;
    public final Object e;

    public G(O o) {
        super(o);
        this.e = new AtomicBoolean(false);
    }

    @Override // androidx.camera.core.AbstractC0199w, java.lang.AutoCloseable
    public void close() {
        switch (this.d) {
            case 1:
                if (!((AtomicBoolean) this.e).getAndSet(true)) {
                    super.close();
                    break;
                }
                break;
            default:
                super.close();
                break;
        }
    }

    public G(O o, H h) {
        super(o);
        this.e = new WeakReference(h);
        a(new F(this, 0));
    }
}
