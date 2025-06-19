package androidx.compose.material3;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class E0 extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ boolean a;
    public final /* synthetic */ Function0 b;
    public final /* synthetic */ boolean c;
    public final /* synthetic */ boolean d;
    public final /* synthetic */ boolean e;
    public final /* synthetic */ String f;
    public final /* synthetic */ C0699p0 g;
    public final /* synthetic */ androidx.compose.runtime.internal.d h;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public E0(boolean z, Function0 function0, boolean z2, boolean z3, boolean z4, String str, C0699p0 c0699p0, androidx.compose.runtime.internal.d dVar, int i) {
        super(2);
        this.a = z;
        this.b = function0;
        this.c = z2;
        this.d = z3;
        this.e = z4;
        this.f = str;
        this.g = c0699p0;
        this.h = dVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        ((Number) obj2).intValue();
        int iH = C0776c.H(805306375);
        C0699p0 c0699p0 = this.g;
        androidx.compose.runtime.internal.d dVar = this.h;
        boolean z = this.e;
        String str = this.f;
        Z0.d(this.a, this.b, this.c, this.d, z, str, c0699p0, dVar, (InterfaceC0806l) obj, iH);
        return Unit.a;
    }
}
