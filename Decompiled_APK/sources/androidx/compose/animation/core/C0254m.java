package androidx.compose.animation.core;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0773a0;
import kotlin.jvm.functions.Function0;

/* renamed from: androidx.compose.animation.core.m, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0254m {
    public final L0 a;
    public final Object b;
    public final long c;
    public final kotlin.jvm.internal.r d;
    public final InterfaceC0773a0 e;
    public AbstractC0267t f;
    public long g;
    public long h = Long.MIN_VALUE;
    public final InterfaceC0773a0 i = C0776c.z(Boolean.TRUE);

    /* JADX WARN: Multi-variable type inference failed */
    public C0254m(Object obj, L0 l0, AbstractC0267t abstractC0267t, long j, Object obj2, long j2, Function0 function0) {
        this.a = l0;
        this.b = obj2;
        this.c = j2;
        this.d = (kotlin.jvm.internal.r) function0;
        this.e = C0776c.z(obj);
        this.f = AbstractC0240f.k(abstractC0267t);
        this.g = j;
    }

    /* JADX WARN: Type inference failed for: r0v2, types: [kotlin.jvm.functions.Function0, kotlin.jvm.internal.r] */
    public final void a() {
        ((androidx.compose.runtime.L0) this.i).setValue(Boolean.FALSE);
        this.d.invoke();
    }
}
