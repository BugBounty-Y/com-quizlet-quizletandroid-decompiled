package androidx.compose.foundation.contextmenu;

import androidx.compose.material3.Z0;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.InterfaceC4938g;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.r;

/* loaded from: classes.dex */
public final class p extends r implements Function2 {
    public final /* synthetic */ int a = 0;
    public final /* synthetic */ boolean b;
    public final /* synthetic */ int c;
    public final /* synthetic */ Object d;
    public final /* synthetic */ Object e;
    public final /* synthetic */ InterfaceC4938g f;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    /* JADX WARN: Multi-variable type inference failed */
    public p(String str, boolean z, c cVar, Function0 function0, int i) {
        super(2);
        this.d = str;
        this.b = z;
        this.e = cVar;
        this.f = (r) function0;
        this.c = i;
    }

    /* JADX WARN: Type inference failed for: r3v1, types: [kotlin.jvm.functions.Function0, kotlin.jvm.internal.r] */
    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Number) obj2).intValue();
                int iH = C0776c.H(this.c | 1);
                ?? r3 = (r) this.f;
                boolean z = this.b;
                c cVar = (c) this.e;
                q.b((String) this.d, z, cVar, r3, (InterfaceC0806l) obj, iH);
                break;
            default:
                ((Number) obj2).intValue();
                int iH2 = C0776c.H(this.c | 1);
                androidx.compose.runtime.internal.d dVar = (androidx.compose.runtime.internal.d) this.f;
                Z0.n((Function0) this.d, this.b, (androidx.compose.ui.n) this.e, dVar, (InterfaceC0806l) obj, iH2);
                break;
        }
        return Unit.a;
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public p(Function0 function0, boolean z, androidx.compose.ui.n nVar, androidx.compose.runtime.internal.d dVar, int i) {
        super(2);
        this.d = function0;
        this.b = z;
        this.e = nVar;
        this.f = dVar;
        this.c = i;
    }
}
