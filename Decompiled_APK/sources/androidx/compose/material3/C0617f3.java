package androidx.compose.material3;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.material3.f3, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0617f3 extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ androidx.compose.ui.q a;
    public final /* synthetic */ long b;
    public final /* synthetic */ float c;
    public final /* synthetic */ long d;
    public final /* synthetic */ int e;
    public final /* synthetic */ int f;
    public final /* synthetic */ int g;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0617f3(androidx.compose.ui.q qVar, long j, float f, long j2, int i, int i2, int i3) {
        super(2);
        this.a = qVar;
        this.b = j;
        this.c = f;
        this.d = j2;
        this.e = i;
        this.f = i2;
        this.g = i3;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        ((Number) obj2).intValue();
        int iH = C0776c.H(this.f | 1);
        float f = this.c;
        AbstractC0666j3.a(this.a, this.b, f, this.d, this.e, (InterfaceC0806l) obj, iH, this.g);
        return Unit.a;
    }
}
