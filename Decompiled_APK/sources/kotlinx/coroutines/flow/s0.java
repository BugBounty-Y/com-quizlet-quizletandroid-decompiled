package kotlinx.coroutines.flow;

import com.android.billingclient.api.C1472a;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.atomic.AtomicReferenceFieldUpdater;
import kotlin.Unit;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C5028l;
import kotlinx.coroutines.flow.internal.AbstractC4993a;
import kotlinx.coroutines.flow.internal.AbstractC4994b;
import kotlinx.coroutines.flow.internal.AbstractC4995c;

/* loaded from: classes3.dex */
public final class s0 extends AbstractC4993a implements X, InterfaceC4992i, kotlinx.coroutines.flow.internal.z {
    public static final /* synthetic */ AtomicReferenceFieldUpdater f = AtomicReferenceFieldUpdater.newUpdater(s0.class, Object.class, "_state$volatile");
    private volatile /* synthetic */ Object _state$volatile;
    public int e;

    public s0(Object obj) {
        this._state$volatile = obj;
    }

    @Override // kotlinx.coroutines.flow.a0
    public final List a() {
        return kotlin.collections.A.b(getValue());
    }

    /* JADX WARN: Code restructure failed: missing block: B:30:0x0078, code lost:
    
        if (((kotlinx.coroutines.flow.v0) r11).a(r0) == r1) goto L60;
     */
    /* JADX WARN: Code restructure failed: missing block: B:46:0x00ad, code lost:
    
        if (r11.equals(r12) == false) goto L47;
     */
    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Path cross not found for [B:45:0x00a9, B:47:0x00af], limit reached: 61 */
    /* JADX WARN: Path cross not found for [B:47:0x00af, B:45:0x00a9], limit reached: 61 */
    /* JADX WARN: Path cross not found for [B:47:0x00af, B:55:0x00ca], limit reached: 61 */
    /* JADX WARN: Removed duplicated region for block: B:39:0x009b A[Catch: all -> 0x0038, TryCatch #1 {all -> 0x0038, blocks: (B:14:0x0034, B:37:0x0093, B:39:0x009b, B:42:0x00a2, B:43:0x00a6, B:45:0x00a9, B:55:0x00ca, B:58:0x00da, B:47:0x00af, B:51:0x00b6, B:21:0x004d, B:24:0x0058, B:36:0x0084), top: B:65:0x0022 }] */
    /* JADX WARN: Removed duplicated region for block: B:45:0x00a9 A[Catch: all -> 0x0038, TryCatch #1 {all -> 0x0038, blocks: (B:14:0x0034, B:37:0x0093, B:39:0x009b, B:42:0x00a2, B:43:0x00a6, B:45:0x00a9, B:55:0x00ca, B:58:0x00da, B:47:0x00af, B:51:0x00b6, B:21:0x004d, B:24:0x0058, B:36:0x0084), top: B:65:0x0022 }] */
    /* JADX WARN: Removed duplicated region for block: B:49:0x00b3  */
    /* JADX WARN: Removed duplicated region for block: B:50:0x00b5  */
    /* JADX WARN: Removed duplicated region for block: B:53:0x00c8  */
    /* JADX WARN: Removed duplicated region for block: B:54:0x00c9  */
    /* JADX WARN: Removed duplicated region for block: B:57:0x00d9  */
    /* JADX WARN: Removed duplicated region for block: B:58:0x00da A[Catch: all -> 0x0038, TRY_LEAVE, TryCatch #1 {all -> 0x0038, blocks: (B:14:0x0034, B:37:0x0093, B:39:0x009b, B:42:0x00a2, B:43:0x00a6, B:45:0x00a9, B:55:0x00ca, B:58:0x00da, B:47:0x00af, B:51:0x00b6, B:21:0x004d, B:24:0x0058, B:36:0x0084), top: B:65:0x0022 }] */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /* JADX WARN: Type inference failed for: r6v0 */
    /* JADX WARN: Type inference failed for: r6v1 */
    /* JADX WARN: Type inference failed for: r6v11 */
    /* JADX WARN: Type inference failed for: r6v12 */
    /* JADX WARN: Type inference failed for: r6v13 */
    /* JADX WARN: Type inference failed for: r6v14 */
    /* JADX WARN: Type inference failed for: r6v2, types: [kotlinx.coroutines.flow.internal.c] */
    /* JADX WARN: Type inference failed for: r6v3 */
    /* JADX WARN: Type inference failed for: r6v7, types: [kotlinx.coroutines.flow.t0] */
    /* JADX WARN: Type inference failed for: r8v1, types: [kotlinx.coroutines.flow.internal.a] */
    /* JADX WARN: Type inference failed for: r8v10 */
    /* JADX WARN: Type inference failed for: r8v11 */
    /* JADX WARN: Type inference failed for: r8v12 */
    /* JADX WARN: Type inference failed for: r8v13 */
    /* JADX WARN: Type inference failed for: r8v2 */
    /* JADX WARN: Type inference failed for: r8v6, types: [java.lang.Object, kotlinx.coroutines.flow.s0] */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:57:0x00d9 -> B:37:0x0093). Please report as a decompilation issue!!! */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:59:0x00ea -> B:37:0x0093). Please report as a decompilation issue!!! */
    @Override // kotlinx.coroutines.flow.InterfaceC4992i
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object b(kotlinx.coroutines.flow.InterfaceC5002j r11, kotlin.coroutines.h r12) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 241
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: kotlinx.coroutines.flow.s0.b(kotlinx.coroutines.flow.j, kotlin.coroutines.h):java.lang.Object");
    }

    @Override // kotlinx.coroutines.flow.internal.z
    public final InterfaceC4992i c(CoroutineContext coroutineContext, int i, kotlinx.coroutines.channels.a aVar) {
        return (((i < 0 || i >= 2) && i != -2) || aVar != kotlinx.coroutines.channels.a.b) ? e0.t(this, coroutineContext, i, aVar) : this;
    }

    @Override // kotlinx.coroutines.flow.internal.AbstractC4993a
    public final AbstractC4995c e() {
        return new t0();
    }

    @Override // kotlinx.coroutines.flow.W, kotlinx.coroutines.flow.InterfaceC5002j
    public final Object emit(Object obj, kotlin.coroutines.h hVar) {
        l(obj);
        return Unit.a;
    }

    @Override // kotlinx.coroutines.flow.internal.AbstractC4993a
    public final AbstractC4995c[] f() {
        return new t0[2];
    }

    @Override // kotlinx.coroutines.flow.W
    public final void g() {
        throw new UnsupportedOperationException("MutableStateFlow.resetReplayCache is not supported");
    }

    @Override // kotlinx.coroutines.flow.q0
    public final Object getValue() {
        C1472a c1472a = AbstractC4994b.b;
        Object obj = f.get(this);
        if (obj == c1472a) {
            return null;
        }
        return obj;
    }

    @Override // kotlinx.coroutines.flow.W
    public final boolean h(Object obj) {
        l(obj);
        return true;
    }

    public final boolean k(Object obj, Object obj2) {
        C1472a c1472a = AbstractC4994b.b;
        if (obj == null) {
            obj = c1472a;
        }
        if (obj2 == null) {
            obj2 = c1472a;
        }
        return m(obj, obj2);
    }

    public final void l(Object obj) {
        if (obj == null) {
            obj = AbstractC4994b.b;
        }
        m(null, obj);
    }

    public final boolean m(Object obj, Object obj2) {
        int i;
        AbstractC4995c[] abstractC4995cArr;
        C1472a c1472a;
        synchronized (this) {
            AtomicReferenceFieldUpdater atomicReferenceFieldUpdater = f;
            Object obj3 = atomicReferenceFieldUpdater.get(this);
            if (obj != null && !Intrinsics.b(obj3, obj)) {
                return false;
            }
            if (Intrinsics.b(obj3, obj2)) {
                return true;
            }
            atomicReferenceFieldUpdater.set(this, obj2);
            int i2 = this.e;
            if ((i2 & 1) != 0) {
                this.e = i2 + 2;
                return true;
            }
            int i3 = i2 + 1;
            this.e = i3;
            AbstractC4995c[] abstractC4995cArr2 = this.a;
            Unit unit = Unit.a;
            while (true) {
                t0[] t0VarArr = (t0[]) abstractC4995cArr2;
                if (t0VarArr != null) {
                    for (t0 t0Var : t0VarArr) {
                        if (t0Var != null) {
                            AtomicReference atomicReference = t0Var.a;
                            while (true) {
                                Object obj4 = atomicReference.get();
                                if (obj4 != null && obj4 != (c1472a = e0.c)) {
                                    C1472a c1472a2 = e0.b;
                                    if (obj4 != c1472a2) {
                                        while (!atomicReference.compareAndSet(obj4, c1472a2)) {
                                            if (atomicReference.get() != obj4) {
                                                break;
                                            }
                                        }
                                        kotlin.p pVar = kotlin.r.b;
                                        ((C5028l) obj4).resumeWith(Unit.a);
                                        break;
                                    }
                                    while (!atomicReference.compareAndSet(obj4, c1472a)) {
                                        if (atomicReference.get() != obj4) {
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                synchronized (this) {
                    i = this.e;
                    if (i == i3) {
                        this.e = i3 + 1;
                        return true;
                    }
                    abstractC4995cArr = this.a;
                    Unit unit2 = Unit.a;
                }
                abstractC4995cArr2 = abstractC4995cArr;
                i3 = i;
            }
        }
    }
}
