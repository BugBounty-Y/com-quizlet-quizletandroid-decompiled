package kotlin.jvm.internal;

/* loaded from: classes3.dex */
public abstract class y extends E implements kotlin.reflect.k {
    @Override // kotlin.jvm.internal.AbstractC4946e
    public kotlin.reflect.b computeReflected() {
        K.a.getClass();
        return this;
    }

    @Override // kotlin.reflect.k
    public Object getDelegate() {
        return ((kotlin.reflect.k) getReflected()).getDelegate();
    }

    public /* bridge */ /* synthetic */ kotlin.reflect.i getGetter() {
        mo150getGetter();
        return null;
    }

    @Override // kotlin.jvm.functions.Function0
    public Object invoke() {
        return get();
    }

    @Override // kotlin.reflect.k
    /* renamed from: getGetter, reason: collision with other method in class */
    public kotlin.reflect.j mo150getGetter() {
        ((kotlin.reflect.k) getReflected()).mo150getGetter();
        return null;
    }
}
