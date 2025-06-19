package kotlinx.coroutines;

import com.android.billingclient.api.C1472a;
import java.util.ArrayList;
import java.util.concurrent.atomic.AtomicIntegerFieldUpdater;
import java.util.concurrent.atomic.AtomicReferenceFieldUpdater;

/* renamed from: kotlinx.coroutines.c, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4976c extends l0 {
    public static final /* synthetic */ AtomicReferenceFieldUpdater h = AtomicReferenceFieldUpdater.newUpdater(C4976c.class, Object.class, "_disposer$volatile");
    private volatile /* synthetic */ Object _disposer$volatile;
    public final C5028l e;
    public Q f;
    public final /* synthetic */ C4980e g;

    public C4976c(C4980e c4980e, C5028l c5028l) {
        this.g = c4980e;
        this.e = c5028l;
    }

    @Override // kotlinx.coroutines.l0
    public final boolean j() {
        return false;
    }

    @Override // kotlinx.coroutines.l0
    public final void k(Throwable th) throws DispatchException {
        C5028l c5028l = this.e;
        if (th != null) {
            c5028l.getClass();
            C1472a c1472aG = c5028l.G(new C5036u(th, false), null);
            if (c1472aG != null) {
                c5028l.t(c1472aG);
                C4978d c4978d = (C4978d) h.get(this);
                if (c4978d != null) {
                    c4978d.a();
                    return;
                }
                return;
            }
            return;
        }
        AtomicIntegerFieldUpdater atomicIntegerFieldUpdater = C4980e.b;
        C4980e c4980e = this.g;
        if (atomicIntegerFieldUpdater.decrementAndGet(c4980e) == 0) {
            H[] hArr = c4980e.a;
            ArrayList arrayList = new ArrayList(hArr.length);
            for (H h2 : hArr) {
                arrayList.add(h2.l());
            }
            kotlin.p pVar = kotlin.r.b;
            c5028l.resumeWith(arrayList);
        }
    }
}
