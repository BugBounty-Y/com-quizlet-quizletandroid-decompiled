package com.google.mlkit.common.sdkinternal;

import com.google.android.gms.common.internal.u;
import java.util.ArrayDeque;
import java.util.Deque;

/* loaded from: classes2.dex */
public final /* synthetic */ class l implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ Runnable b;

    public /* synthetic */ l(Runnable runnable, int i) {
        this.a = i;
        this.b = runnable;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                Deque deque = (Deque) g.b.get();
                u.h(deque);
                Runnable runnable = this.b;
                deque.add(runnable);
                if (deque.size() <= 1) {
                    do {
                        runnable.run();
                        deque.removeFirst();
                        runnable = (Runnable) deque.peekFirst();
                    } while (runnable != null);
                }
                break;
            default:
                g.b.set(new ArrayDeque());
                this.b.run();
                break;
        }
    }
}
