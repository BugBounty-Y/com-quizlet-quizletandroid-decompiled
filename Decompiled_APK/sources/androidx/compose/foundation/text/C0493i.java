package androidx.compose.foundation.text;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.foundation.text.i, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0493i extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ androidx.compose.ui.text.input.A a;
    public final /* synthetic */ Function1 b;
    public final /* synthetic */ androidx.compose.ui.q c;
    public final /* synthetic */ boolean d;
    public final /* synthetic */ androidx.compose.ui.text.L e;
    public final /* synthetic */ C0490g0 f;
    public final /* synthetic */ C0488f0 g;
    public final /* synthetic */ boolean h;
    public final /* synthetic */ int i;
    public final /* synthetic */ int j;
    public final /* synthetic */ androidx.compose.ui.text.input.K k;
    public final /* synthetic */ C0491h l;
    public final /* synthetic */ androidx.compose.foundation.interaction.l m;
    public final /* synthetic */ androidx.compose.ui.graphics.X n;
    public final /* synthetic */ androidx.compose.runtime.internal.d o;
    public final /* synthetic */ int p;
    public final /* synthetic */ int q;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0493i(androidx.compose.ui.text.input.A a, Function1 function1, androidx.compose.ui.q qVar, boolean z, androidx.compose.ui.text.L l, C0490g0 c0490g0, C0488f0 c0488f0, boolean z2, int i, int i2, androidx.compose.ui.text.input.K k, C0491h c0491h, androidx.compose.foundation.interaction.l lVar, androidx.compose.ui.graphics.X x, androidx.compose.runtime.internal.d dVar, int i3, int i4, int i5) {
        super(2);
        this.a = a;
        this.b = function1;
        this.c = qVar;
        this.d = z;
        this.e = l;
        this.f = c0490g0;
        this.g = c0488f0;
        this.h = z2;
        this.i = i;
        this.j = i2;
        this.k = k;
        this.l = c0491h;
        this.m = lVar;
        this.n = x;
        this.o = dVar;
        this.p = i4;
        this.q = i5;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        ((Number) obj2).intValue();
        int iH = C0776c.H(1);
        int iH2 = C0776c.H(this.p);
        androidx.compose.ui.graphics.X x = this.n;
        androidx.compose.runtime.internal.d dVar = this.o;
        C0490g0 c0490g0 = this.f;
        androidx.compose.foundation.interaction.l lVar = this.m;
        int i = this.q;
        AbstractC0503k.a(this.a, this.b, this.c, this.d, this.e, c0490g0, this.g, this.h, this.i, this.j, this.k, this.l, lVar, x, dVar, (InterfaceC0806l) obj, iH, iH2, i);
        return Unit.a;
    }
}
