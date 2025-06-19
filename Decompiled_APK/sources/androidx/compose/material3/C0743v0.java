package androidx.compose.material3;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.material3.v0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0743v0 extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ int a = 0;
    public final /* synthetic */ boolean b;
    public final /* synthetic */ androidx.compose.ui.q c;
    public final /* synthetic */ androidx.compose.runtime.internal.d d;
    public final /* synthetic */ Object e;
    public final /* synthetic */ Object f;
    public final /* synthetic */ Object g;
    public final /* synthetic */ Object h;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0743v0(C0585a1 c0585a1, androidx.compose.ui.q qVar, C0716s0 c0716s0, androidx.compose.runtime.internal.d dVar, androidx.compose.runtime.internal.d dVar2, boolean z, C0699p0 c0699p0, int i) {
        super(2);
        this.e = c0585a1;
        this.c = qVar;
        this.f = c0716s0;
        this.d = dVar;
        this.g = dVar2;
        this.b = z;
        this.h = c0699p0;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Number) obj2).intValue();
                int iH = C0776c.H(224257);
                C0699p0 c0699p0 = (C0699p0) this.h;
                C0585a1 c0585a1 = (C0585a1) this.e;
                androidx.compose.runtime.internal.d dVar = this.d;
                androidx.compose.runtime.internal.d dVar2 = (androidx.compose.runtime.internal.d) this.g;
                Z0.b(c0585a1, this.c, (C0716s0) this.f, dVar, dVar2, this.b, c0699p0, (InterfaceC0806l) obj, iH);
                break;
            default:
                ((Number) obj2).intValue();
                int iH2 = C0776c.H(1597441);
                androidx.compose.runtime.internal.d dVar3 = this.d;
                androidx.compose.ui.i iVar = (androidx.compose.ui.i) this.g;
                androidx.compose.material3.pulltorefresh.g.a(this.b, (Function0) this.e, this.c, (androidx.compose.material3.pulltorefresh.q) this.f, iVar, (kotlin.jvm.functions.c) this.h, dVar3, (InterfaceC0806l) obj, iH2);
                break;
        }
        return Unit.a;
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0743v0(boolean z, Function0 function0, androidx.compose.ui.q qVar, androidx.compose.material3.pulltorefresh.q qVar2, androidx.compose.ui.i iVar, kotlin.jvm.functions.c cVar, androidx.compose.runtime.internal.d dVar, int i) {
        super(2);
        this.b = z;
        this.e = function0;
        this.c = qVar;
        this.f = qVar2;
        this.g = iVar;
        this.h = cVar;
        this.d = dVar;
    }
}
