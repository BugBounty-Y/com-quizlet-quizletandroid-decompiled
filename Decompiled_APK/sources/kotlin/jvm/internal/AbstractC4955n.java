package kotlin.jvm.internal;

/* renamed from: kotlin.jvm.internal.n, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public abstract class AbstractC4955n extends AbstractC4946e implements InterfaceC4954m, kotlin.reflect.f {
    private final int arity;
    private final int flags;

    public AbstractC4955n(int i, int i2, Class cls, Object obj, String str, String str2) {
        super(obj, cls, str, str2, (i2 & 1) == 1);
        this.arity = i;
        this.flags = 0;
    }

    @Override // kotlin.jvm.internal.AbstractC4946e
    public kotlin.reflect.b computeReflected() {
        K.a.getClass();
        return this;
    }

    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof AbstractC4955n) {
            AbstractC4955n abstractC4955n = (AbstractC4955n) obj;
            return getName().equals(abstractC4955n.getName()) && getSignature().equals(abstractC4955n.getSignature()) && this.flags == abstractC4955n.flags && this.arity == abstractC4955n.arity && Intrinsics.b(getBoundReceiver(), abstractC4955n.getBoundReceiver()) && Intrinsics.b(getOwner(), abstractC4955n.getOwner());
        }
        if (obj instanceof kotlin.reflect.f) {
            return obj.equals(compute());
        }
        return false;
    }

    @Override // kotlin.jvm.internal.InterfaceC4954m
    public int getArity() {
        return this.arity;
    }

    public int hashCode() {
        return getSignature().hashCode() + ((getName().hashCode() + (getOwner() == null ? 0 : getOwner().hashCode() * 31)) * 31);
    }

    @Override // kotlin.jvm.internal.AbstractC4946e, kotlin.reflect.b
    public boolean isSuspend() {
        return getReflected().isSuspend();
    }

    public String toString() {
        kotlin.reflect.b bVarCompute = compute();
        if (bVarCompute != this) {
            return bVarCompute.toString();
        }
        if ("<init>".equals(getName())) {
            return "constructor (Kotlin reflection is not available)";
        }
        return "function " + getName() + " (Kotlin reflection is not available)";
    }

    @Override // kotlin.jvm.internal.AbstractC4946e
    public kotlin.reflect.f getReflected() {
        return (kotlin.reflect.f) super.getReflected();
    }
}
