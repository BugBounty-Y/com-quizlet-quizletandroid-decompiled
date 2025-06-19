package androidx.transition;

import android.view.ViewGroup;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3367m2;

/* renamed from: androidx.transition.c, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1400c extends z {
    public boolean a = false;
    public final ViewGroup b;

    public C1400c(ViewGroup viewGroup) {
        this.b = viewGroup;
    }

    @Override // androidx.transition.z, androidx.transition.InterfaceC1419w
    public final void a() {
        AbstractC3367m2.b(this.b, false);
    }

    @Override // androidx.transition.z, androidx.transition.InterfaceC1419w
    public final void d(y yVar) {
        if (!this.a) {
            AbstractC3367m2.b(this.b, false);
        }
        yVar.D(this);
    }

    @Override // androidx.transition.z, androidx.transition.InterfaceC1419w
    public final void f(y yVar) {
        AbstractC3367m2.b(this.b, false);
        this.a = true;
    }

    @Override // androidx.transition.z, androidx.transition.InterfaceC1419w
    public final void g() {
        AbstractC3367m2.b(this.b, true);
    }
}
