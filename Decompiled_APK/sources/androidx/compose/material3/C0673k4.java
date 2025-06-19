package androidx.compose.material3;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.material3.k4, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0673k4 extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ androidx.compose.ui.q a;
    public final /* synthetic */ boolean b;
    public final /* synthetic */ boolean c;
    public final /* synthetic */ C0636i4 d;
    public final /* synthetic */ androidx.compose.foundation.interaction.l e;
    public final /* synthetic */ androidx.compose.ui.graphics.V f;
    public final /* synthetic */ int g;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0673k4(androidx.compose.ui.q qVar, boolean z, boolean z2, C0636i4 c0636i4, androidx.compose.foundation.interaction.l lVar, androidx.compose.ui.graphics.V v, int i) {
        super(2);
        this.a = qVar;
        this.b = z;
        this.c = z2;
        this.d = c0636i4;
        this.e = lVar;
        this.f = v;
        this.g = i;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        ((Number) obj2).intValue();
        int iH = C0776c.H(this.g | 1);
        boolean z = this.c;
        C0636i4 c0636i4 = this.d;
        AbstractC0679l4.b(this.a, this.b, z, c0636i4, this.e, this.f, (InterfaceC0806l) obj, iH);
        return Unit.a;
    }
}
