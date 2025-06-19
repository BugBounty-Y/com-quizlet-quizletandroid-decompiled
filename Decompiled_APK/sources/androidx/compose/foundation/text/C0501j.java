package androidx.compose.foundation.text;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.graphics.AbstractC0857q;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.foundation.text.j, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0501j extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ int a = 1;
    public final /* synthetic */ Function1 b;
    public final /* synthetic */ androidx.compose.ui.q c;
    public final /* synthetic */ androidx.compose.ui.text.L d;
    public final /* synthetic */ androidx.compose.ui.text.input.K e;
    public final /* synthetic */ androidx.compose.foundation.interaction.l f;
    public final /* synthetic */ AbstractC0857q g;
    public final /* synthetic */ boolean h;
    public final /* synthetic */ int i;
    public final /* synthetic */ int j;
    public final /* synthetic */ C0488f0 k;
    public final /* synthetic */ boolean l;
    public final /* synthetic */ boolean m;
    public final /* synthetic */ androidx.compose.runtime.internal.d n;
    public final /* synthetic */ int o;
    public final /* synthetic */ int p;
    public final /* synthetic */ Object q;
    public final /* synthetic */ Object r;
    public final /* synthetic */ Object s;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    /* JADX WARN: Multi-variable type inference failed */
    public C0501j(androidx.compose.ui.text.input.A a, Function1 function1, androidx.compose.ui.q qVar, androidx.compose.ui.text.L l, androidx.compose.ui.text.input.K k, Function1 function12, androidx.compose.foundation.interaction.l lVar, AbstractC0857q abstractC0857q, boolean z, int i, int i2, androidx.compose.ui.text.input.m mVar, C0488f0 c0488f0, boolean z2, boolean z3, androidx.compose.runtime.internal.d dVar, int i3, int i4) {
        super(2);
        this.q = a;
        this.b = function1;
        this.c = qVar;
        this.d = l;
        this.e = k;
        this.r = (kotlin.jvm.internal.r) function12;
        this.f = lVar;
        this.g = abstractC0857q;
        this.h = z;
        this.i = i;
        this.j = i2;
        this.s = mVar;
        this.k = c0488f0;
        this.l = z2;
        this.m = z3;
        this.n = dVar;
        this.o = i3;
        this.p = i4;
    }

    /* JADX WARN: Type inference failed for: r7v2, types: [kotlin.jvm.functions.Function1, kotlin.jvm.internal.r] */
    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        InterfaceC0806l interfaceC0806l = (InterfaceC0806l) obj;
        switch (this.a) {
            case 0:
                ((Number) obj2).intValue();
                int iH = C0776c.H(this.o | 1);
                AbstractC0857q abstractC0857q = this.g;
                androidx.compose.runtime.internal.d dVar = this.n;
                AbstractC0503k.b((String) this.q, this.b, this.c, this.h, this.l, this.d, (C0490g0) this.r, this.k, this.m, this.i, this.j, this.e, (C0491h) this.s, this.f, abstractC0857q, dVar, interfaceC0806l, iH, this.p);
                break;
            default:
                ((Number) obj2).intValue();
                int iH2 = C0776c.H(this.o | 1);
                int iH3 = C0776c.H(this.p);
                androidx.compose.runtime.internal.d dVar2 = this.n;
                AbstractC0484d0.f((androidx.compose.ui.text.input.A) this.q, this.b, this.c, this.d, this.e, (kotlin.jvm.internal.r) this.r, this.f, this.g, this.h, this.i, this.j, (androidx.compose.ui.text.input.m) this.s, this.k, this.l, this.m, dVar2, interfaceC0806l, iH2, iH3);
                break;
        }
        return Unit.a;
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0501j(String str, Function1 function1, androidx.compose.ui.q qVar, boolean z, boolean z2, androidx.compose.ui.text.L l, C0490g0 c0490g0, C0488f0 c0488f0, boolean z3, int i, int i2, androidx.compose.ui.text.input.K k, C0491h c0491h, androidx.compose.foundation.interaction.l lVar, AbstractC0857q abstractC0857q, androidx.compose.runtime.internal.d dVar, int i3, int i4) {
        super(2);
        this.q = str;
        this.b = function1;
        this.c = qVar;
        this.h = z;
        this.l = z2;
        this.d = l;
        this.r = c0490g0;
        this.k = c0488f0;
        this.m = z3;
        this.i = i;
        this.j = i2;
        this.e = k;
        this.s = c0491h;
        this.f = lVar;
        this.g = abstractC0857q;
        this.n = dVar;
        this.o = i3;
        this.p = i4;
    }
}
