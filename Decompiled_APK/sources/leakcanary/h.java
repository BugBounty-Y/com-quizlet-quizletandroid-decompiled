package leakcanary;

import android.os.MessageQueue;

/* loaded from: classes3.dex */
public final class h implements MessageQueue.IdleHandler {
    public final /* synthetic */ i a;

    public h(i iVar) {
        this.a = iVar;
    }

    @Override // android.os.MessageQueue.IdleHandler
    public final boolean queueIdle() {
        this.a.b.invoke();
        return true;
    }
}
