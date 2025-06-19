package androidx.compose.material3;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.material3.p4, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0703p4 extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ long a;
    public final /* synthetic */ long b;
    public final /* synthetic */ boolean c;
    public final /* synthetic */ androidx.compose.runtime.internal.d d;
    public final /* synthetic */ int e;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0703p4(long j, long j2, boolean z, androidx.compose.runtime.internal.d dVar, int i) {
        super(2);
        this.a = j;
        this.b = j2;
        this.c = z;
        this.d = dVar;
        this.e = i;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        ((Number) obj2).intValue();
        int iH = C0776c.H(this.e | 1);
        androidx.compose.runtime.internal.d dVar = this.d;
        AbstractC0709q4.c(this.a, this.b, this.c, dVar, (InterfaceC0806l) obj, iH);
        return Unit.a;
    }
}
