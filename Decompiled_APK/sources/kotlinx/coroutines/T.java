package kotlinx.coroutines;

/* loaded from: classes3.dex */
public final class T implements InterfaceC4981e0 {
    public final boolean a;

    public T(boolean z) {
        this.a = z;
    }

    @Override // kotlinx.coroutines.InterfaceC4981e0
    public final boolean a() {
        return this.a;
    }

    @Override // kotlinx.coroutines.InterfaceC4981e0
    public final t0 b() {
        return null;
    }

    public final String toString() {
        return androidx.compose.animation.d0.r(new StringBuilder("Empty{"), this.a ? "Active" : "New", '}');
    }
}
