package androidx.compose.animation.core;

import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.animation.core.r0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0264r0 extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ kotlin.jvm.internal.J a;
    public final /* synthetic */ float b;
    public final /* synthetic */ InterfaceC0250k c;
    public final /* synthetic */ C0258o d;
    public final /* synthetic */ Function1 e;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0264r0(kotlin.jvm.internal.J j, float f, InterfaceC0250k interfaceC0250k, C0258o c0258o, Function1 function1) {
        super(1);
        this.a = j;
        this.b = f;
        this.c = interfaceC0250k;
        this.d = c0258o;
        this.e = function1;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        long jLongValue = ((Number) obj).longValue();
        Object obj2 = this.a.a;
        Intrinsics.d(obj2);
        AbstractC0240f.m((C0254m) obj2, jLongValue, this.b, this.c, this.d, this.e);
        return Unit.a;
    }
}
