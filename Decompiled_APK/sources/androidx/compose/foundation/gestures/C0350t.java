package androidx.compose.foundation.gestures;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0773a0;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.foundation.gestures.t, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0350t implements E0 {
    public final kotlin.jvm.internal.r a;
    public final C0348s b = new C0348s(this);
    public final androidx.compose.foundation.y0 c = new androidx.compose.foundation.y0();
    public final InterfaceC0773a0 d;
    public final InterfaceC0773a0 e;
    public final InterfaceC0773a0 f;

    /* JADX WARN: Multi-variable type inference failed */
    public C0350t(Function1 function1) {
        this.a = (kotlin.jvm.internal.r) function1;
        Boolean bool = Boolean.FALSE;
        this.d = C0776c.z(bool);
        this.e = C0776c.z(bool);
        this.f = C0776c.z(bool);
    }

    @Override // androidx.compose.foundation.gestures.E0
    public final boolean a() {
        return ((Boolean) ((androidx.compose.runtime.L0) this.d).getValue()).booleanValue();
    }

    @Override // androidx.compose.foundation.gestures.E0
    public final Object c(androidx.compose.foundation.u0 u0Var, Function2 function2, kotlin.coroutines.jvm.internal.c cVar) {
        Object objM = kotlinx.coroutines.E.m(new r(this, u0Var, function2, null), cVar);
        return objM == kotlin.coroutines.intrinsics.a.a ? objM : Unit.a;
    }

    /* JADX WARN: Type inference failed for: r0v0, types: [kotlin.jvm.functions.Function1, kotlin.jvm.internal.r] */
    @Override // androidx.compose.foundation.gestures.E0
    public final float e(float f) {
        return ((Number) this.a.invoke(Float.valueOf(f))).floatValue();
    }
}
