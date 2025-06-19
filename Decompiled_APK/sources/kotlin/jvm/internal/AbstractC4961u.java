package kotlin.jvm.internal;

/* renamed from: kotlin.jvm.internal.u, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public abstract class AbstractC4961u extends w implements kotlin.reflect.h {
    @Override // kotlin.jvm.internal.AbstractC4946e
    public final kotlin.reflect.b computeReflected() {
        K.a.getClass();
        return this;
    }

    @Override // kotlin.reflect.l
    public final void getGetter() {
        ((AbstractC4961u) ((kotlin.reflect.h) getReflected())).getGetter();
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        ((v) this).getGetter();
        throw null;
    }
}
