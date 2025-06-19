package androidx.compose.foundation.lazy.layout;

import androidx.compose.foundation.gestures.InterfaceC0334k0;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.foundation.lazy.layout.j, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0438j extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public kotlin.jvm.internal.F j;
    public kotlin.jvm.internal.J k;
    public kotlin.jvm.internal.H l;
    public float m;
    public float n;
    public float o;
    public int p;
    public int q;
    public /* synthetic */ Object r;
    public final /* synthetic */ int s;
    public final /* synthetic */ androidx.compose.ui.unit.b t;
    public final /* synthetic */ InterfaceC0440l u;
    public final /* synthetic */ int v;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0438j(int i, androidx.compose.ui.unit.b bVar, InterfaceC0440l interfaceC0440l, int i2, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.s = i;
        this.t = bVar;
        this.u = interfaceC0440l;
        this.v = i2;
    }

    public static final boolean a(boolean z, InterfaceC0440l interfaceC0440l, int i, int i2) {
        if (z) {
            if (interfaceC0440l.y() > i) {
                return true;
            }
            return interfaceC0440l.y() == i && interfaceC0440l.u() > i2;
        }
        if (interfaceC0440l.y() < i) {
            return true;
        }
        return interfaceC0440l.y() == i && interfaceC0440l.u() < i2;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        C0438j c0438j = new C0438j(this.s, this.t, this.u, this.v, hVar);
        c0438j.r = obj;
        return c0438j;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C0438j) create((InterfaceC0334k0) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:67:0x01c3, code lost:
    
        if (androidx.compose.animation.core.AbstractC0240f.i(r1, r1, null, !r12, r4, r30, 2) == r7) goto L68;
     */
    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:26:0x00a4 A[Catch: h -> 0x00c5, TryCatch #0 {h -> 0x00c5, blocks: (B:55:0x0153, B:24:0x00a0, B:26:0x00a4, B:28:0x00aa, B:30:0x00b8, B:39:0x00cf, B:43:0x00fa, B:47:0x0107, B:51:0x0144), top: B:74:0x0153 }] */
    /* JADX WARN: Removed duplicated region for block: B:30:0x00b8 A[Catch: h -> 0x00c5, TryCatch #0 {h -> 0x00c5, blocks: (B:55:0x0153, B:24:0x00a0, B:26:0x00a4, B:28:0x00aa, B:30:0x00b8, B:39:0x00cf, B:43:0x00fa, B:47:0x0107, B:51:0x0144), top: B:74:0x0153 }] */
    /* JADX WARN: Removed duplicated region for block: B:36:0x00ca  */
    /* JADX WARN: Removed duplicated region for block: B:41:0x00f7  */
    /* JADX WARN: Removed duplicated region for block: B:42:0x00f9  */
    /* JADX WARN: Removed duplicated region for block: B:45:0x0102  */
    /* JADX WARN: Removed duplicated region for block: B:46:0x0105  */
    /* JADX WARN: Removed duplicated region for block: B:53:0x014a  */
    /* JADX WARN: Removed duplicated region for block: B:54:0x014c  */
    /* JADX WARN: Removed duplicated region for block: B:63:0x01a0  */
    /* JADX WARN: Removed duplicated region for block: B:65:0x01a4  */
    /* JADX WARN: Type inference failed for: r10v0 */
    /* JADX WARN: Type inference failed for: r10v5 */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:54:0x014c -> B:74:0x0153). Please report as a decompilation issue!!! */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r31) {
        /*
            Method dump skipped, instructions count: 478
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.lazy.layout.C0438j.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
