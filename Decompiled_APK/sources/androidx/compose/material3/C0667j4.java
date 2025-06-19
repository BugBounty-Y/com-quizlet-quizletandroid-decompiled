package androidx.compose.material3;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.material3.j4, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0667j4 extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ boolean a;
    public final /* synthetic */ Function1 b;
    public final /* synthetic */ androidx.compose.ui.q c;
    public final /* synthetic */ boolean d;
    public final /* synthetic */ C0636i4 e;
    public final /* synthetic */ int f;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0667j4(boolean z, Function1 function1, androidx.compose.ui.q qVar, boolean z2, C0636i4 c0636i4, int i) {
        super(2);
        this.a = z;
        this.b = function1;
        this.c = qVar;
        this.d = z2;
        this.e = c0636i4;
        this.f = i;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        ((Number) obj2).intValue();
        int iH = C0776c.H(this.f | 1);
        androidx.compose.ui.q qVar = this.c;
        boolean z = this.d;
        AbstractC0679l4.a(this.a, this.b, qVar, z, this.e, (InterfaceC0806l) obj, iH);
        return Unit.a;
    }
}
