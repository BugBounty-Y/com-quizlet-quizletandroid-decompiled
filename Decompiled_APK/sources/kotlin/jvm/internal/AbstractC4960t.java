package kotlin.jvm.internal;

/* renamed from: kotlin.jvm.internal.t, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public abstract class AbstractC4960t extends w implements kotlin.reflect.g {
    @Override // kotlin.jvm.internal.AbstractC4946e
    public final kotlin.reflect.b computeReflected() {
        K.a.getClass();
        return this;
    }

    @Override // kotlin.reflect.k
    public final Object getDelegate() {
        return ((AbstractC4960t) ((kotlin.reflect.g) getReflected())).getDelegate();
    }

    @Override // kotlin.reflect.k
    /* renamed from: getGetter */
    public final kotlin.reflect.j mo150getGetter() {
        ((AbstractC4960t) ((kotlin.reflect.g) getReflected())).mo150getGetter();
        return null;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        return get();
    }
}
