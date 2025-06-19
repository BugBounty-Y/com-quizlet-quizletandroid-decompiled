package androidx.compose.material3;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.material3.i3, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0635i3 extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ Function0 a;
    public final /* synthetic */ androidx.compose.ui.q b;
    public final /* synthetic */ long c;
    public final /* synthetic */ long d;
    public final /* synthetic */ int e;
    public final /* synthetic */ float f;
    public final /* synthetic */ Function1 g;
    public final /* synthetic */ int h;
    public final /* synthetic */ int i;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0635i3(Function0 function0, androidx.compose.ui.q qVar, long j, long j2, int i, float f, Function1 function1, int i2, int i3) {
        super(2);
        this.a = function0;
        this.b = qVar;
        this.c = j;
        this.d = j2;
        this.e = i;
        this.f = f;
        this.g = function1;
        this.h = i2;
        this.i = i3;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        ((Number) obj2).intValue();
        int iH = C0776c.H(this.h | 1);
        int i = this.e;
        AbstractC0666j3.b(this.a, this.b, this.c, this.d, i, this.f, this.g, (InterfaceC0806l) obj, iH, this.i);
        return Unit.a;
    }
}
