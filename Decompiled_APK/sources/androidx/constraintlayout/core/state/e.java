package androidx.constraintlayout.core.state;

/* loaded from: classes.dex */
public final class e implements d {
    public float a;
    public float b;

    @Override // androidx.constraintlayout.core.state.d
    public final float value() {
        float f = this.b + this.a;
        this.b = f;
        return f;
    }
}
