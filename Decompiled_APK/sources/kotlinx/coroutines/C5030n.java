package kotlinx.coroutines;

import com.android.billingclient.api.C1472a;
import java.util.concurrent.atomic.AtomicReferenceFieldUpdater;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: kotlinx.coroutines.n, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C5030n extends l0 {
    public final /* synthetic */ int e;
    public final C5028l f;

    public /* synthetic */ C5030n(C5028l c5028l, int i) {
        this.e = i;
        this.f = c5028l;
    }

    @Override // kotlinx.coroutines.l0
    public final boolean j() {
        switch (this.e) {
            case 0:
                return true;
            default:
                return false;
        }
    }

    @Override // kotlinx.coroutines.l0
    public final void k(Throwable th) {
        C5028l c5028l = this.f;
        switch (this.e) {
            case 0:
                Throwable thP = c5028l.p(i());
                if (c5028l.z()) {
                    kotlin.coroutines.h hVar = c5028l.d;
                    Intrinsics.e(hVar, "null cannot be cast to non-null type kotlinx.coroutines.internal.DispatchedContinuation<*>");
                    kotlinx.coroutines.internal.f fVar = (kotlinx.coroutines.internal.f) hVar;
                    while (true) {
                        AtomicReferenceFieldUpdater atomicReferenceFieldUpdater = kotlinx.coroutines.internal.f.h;
                        Object obj = atomicReferenceFieldUpdater.get(fVar);
                        C1472a c1472a = kotlinx.coroutines.internal.b.c;
                        if (Intrinsics.b(obj, c1472a)) {
                            while (!atomicReferenceFieldUpdater.compareAndSet(fVar, c1472a, thP)) {
                                if (atomicReferenceFieldUpdater.get(fVar) != c1472a) {
                                    break;
                                }
                            }
                            break;
                        } else if (obj instanceof Throwable) {
                            break;
                        } else {
                            while (!atomicReferenceFieldUpdater.compareAndSet(fVar, obj, null)) {
                                if (atomicReferenceFieldUpdater.get(fVar) != obj) {
                                    break;
                                }
                            }
                        }
                    }
                }
                c5028l.b(thP);
                if (!c5028l.z()) {
                    c5028l.n();
                    break;
                }
                break;
            default:
                kotlin.p pVar = kotlin.r.b;
                c5028l.resumeWith(Unit.a);
                break;
        }
    }
}
