package kotlin.jvm.internal;

/* loaded from: classes3.dex */
public abstract class A extends E implements kotlin.reflect.l {
    @Override // kotlin.jvm.internal.AbstractC4946e
    public final kotlin.reflect.b computeReflected() {
        K.a.getClass();
        return this;
    }

    @Override // kotlin.reflect.l
    public final void getGetter() {
        ((kotlin.reflect.l) getReflected()).getGetter();
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        return get(obj);
    }
}
