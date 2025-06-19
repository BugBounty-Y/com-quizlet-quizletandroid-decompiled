package androidx.compose.animation.core;

import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* renamed from: androidx.compose.animation.core.q0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0263q0 extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ kotlin.jvm.internal.J a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ InterfaceC0250k c;
    public final /* synthetic */ AbstractC0267t d;
    public final /* synthetic */ C0258o e;
    public final /* synthetic */ float f;
    public final /* synthetic */ Function1 g;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0263q0(kotlin.jvm.internal.J j, Object obj, InterfaceC0250k interfaceC0250k, AbstractC0267t abstractC0267t, C0258o c0258o, float f, Function1 function1) {
        super(1);
        this.a = j;
        this.b = obj;
        this.c = interfaceC0250k;
        this.d = abstractC0267t;
        this.e = c0258o;
        this.f = f;
        this.g = function1;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        long jLongValue = ((Number) obj).longValue();
        InterfaceC0250k interfaceC0250k = this.c;
        L0 l0C = interfaceC0250k.c();
        Object objG = interfaceC0250k.g();
        C0261p0 c0261p0 = new C0261p0(0, this.e);
        C0254m c0254m = new C0254m(this.b, l0C, this.d, jLongValue, objG, jLongValue, c0261p0);
        AbstractC0240f.m(c0254m, jLongValue, this.f, this.c, this.e, this.g);
        this.a.a = c0254m;
        return Unit.a;
    }
}
