package kotlin.jvm.internal;

/* loaded from: classes3.dex */
public abstract class E extends AbstractC4946e implements kotlin.reflect.n {
    private final boolean syntheticJavaProperty;

    public E() {
        this.syntheticJavaProperty = false;
    }

    @Override // kotlin.jvm.internal.AbstractC4946e
    public kotlin.reflect.b compute() {
        return this.syntheticJavaProperty ? this : super.compute();
    }

    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof E) {
            E e = (E) obj;
            return getOwner().equals(e.getOwner()) && getName().equals(e.getName()) && getSignature().equals(e.getSignature()) && Intrinsics.b(getBoundReceiver(), e.getBoundReceiver());
        }
        if (obj instanceof kotlin.reflect.n) {
            return obj.equals(compute());
        }
        return false;
    }

    public int hashCode() {
        return getSignature().hashCode() + ((getName().hashCode() + (getOwner().hashCode() * 31)) * 31);
    }

    @Override // kotlin.reflect.n
    public boolean isConst() {
        return getReflected().isConst();
    }

    @Override // kotlin.reflect.n
    public boolean isLateinit() {
        return getReflected().isLateinit();
    }

    public String toString() {
        kotlin.reflect.b bVarCompute = compute();
        if (bVarCompute != this) {
            return bVarCompute.toString();
        }
        return "property " + getName() + " (Kotlin reflection is not available)";
    }

    @Override // kotlin.jvm.internal.AbstractC4946e
    public kotlin.reflect.n getReflected() {
        if (this.syntheticJavaProperty) {
            throw new UnsupportedOperationException("Kotlin reflection is not yet supported for synthetic Java properties. Please follow/upvote https://youtrack.jetbrains.com/issue/KT-55980");
        }
        return (kotlin.reflect.n) super.getReflected();
    }

    public E(Object obj, Class cls, String str, String str2, int i) {
        super(obj, cls, str, str2, (i & 1) == 1);
        this.syntheticJavaProperty = (i & 2) == 2;
    }
}
