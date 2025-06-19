package androidx.compose.material3;

import androidx.compose.material3.internal.C0659x;
import kotlin.Pair;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.material3.d4, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0606d4 extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ C0624g4 a;
    public final /* synthetic */ boolean b;
    public final /* synthetic */ boolean c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0606d4(C0624g4 c0624g4, boolean z, boolean z2) {
        super(2);
        this.a = c0624g4;
        this.b = z;
        this.c = z2;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        long j = ((androidx.compose.ui.unit.j) obj).a;
        long j2 = ((androidx.compose.ui.unit.a) obj2).a;
        C0600c4 c0600c4 = new C0600c4((int) (j >> 32), this.b, this.c);
        C0659x c0659x = new C0659x();
        c0600c4.invoke(c0659x);
        return new Pair(new androidx.compose.material3.internal.F(c0659x.a), (EnumC0630h4) ((androidx.compose.runtime.E) this.a.b.h).getValue());
    }
}
