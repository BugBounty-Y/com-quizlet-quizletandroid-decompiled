package androidx.fragment.app;

import java.util.concurrent.atomic.AtomicReference;

/* renamed from: androidx.fragment.app.v, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1153v extends androidx.activity.result.b {
    public final /* synthetic */ AtomicReference a;

    public C1153v(AtomicReference atomicReference) {
        this.a = atomicReference;
    }

    @Override // androidx.activity.result.b
    public final void a(Object obj) {
        androidx.activity.result.b bVar = (androidx.activity.result.b) this.a.get();
        if (bVar == null) {
            throw new IllegalStateException("Operation cannot be started before fragment is in created state");
        }
        bVar.a(obj);
    }
}
