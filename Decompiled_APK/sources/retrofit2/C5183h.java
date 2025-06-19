package retrofit2;

import java.util.concurrent.CompletableFuture;

/* renamed from: retrofit2.h, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C5183h extends CompletableFuture {
    public final u a;

    public C5183h(u uVar) {
        this.a = uVar;
    }

    @Override // java.util.concurrent.CompletableFuture, java.util.concurrent.Future
    public final boolean cancel(boolean z) {
        if (z) {
            this.a.cancel();
        }
        return super.cancel(z);
    }
}
