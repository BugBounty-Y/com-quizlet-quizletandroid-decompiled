package androidx.transition;

import androidx.collection.C0208f;
import java.util.ArrayList;

/* loaded from: classes.dex */
public final class A extends z {
    public final /* synthetic */ C0208f a;
    public final /* synthetic */ B b;

    public A(B b, C0208f c0208f) {
        this.b = b;
        this.a = c0208f;
    }

    @Override // androidx.transition.z, androidx.transition.InterfaceC1419w
    public final void d(y yVar) {
        ((ArrayList) this.a.get(this.b.b)).remove(yVar);
        yVar.D(this);
    }
}
