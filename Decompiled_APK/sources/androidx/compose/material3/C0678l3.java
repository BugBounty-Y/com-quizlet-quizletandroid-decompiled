package androidx.compose.material3;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.material3.l3, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0678l3 extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ boolean a;
    public final /* synthetic */ Function0 b;
    public final /* synthetic */ androidx.compose.ui.q c;
    public final /* synthetic */ boolean d;
    public final /* synthetic */ C0672k3 e;
    public final /* synthetic */ int f;
    public final /* synthetic */ int g;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0678l3(boolean z, Function0 function0, androidx.compose.ui.q qVar, boolean z2, C0672k3 c0672k3, int i, int i2) {
        super(2);
        this.a = z;
        this.b = function0;
        this.c = qVar;
        this.d = z2;
        this.e = c0672k3;
        this.f = i;
        this.g = i2;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        ((Number) obj2).intValue();
        int iH = C0776c.H(this.f | 1);
        boolean z = this.d;
        AbstractC0684m3.a(this.a, this.b, this.c, z, this.e, (InterfaceC0806l) obj, iH, this.g);
        return Unit.a;
    }
}
