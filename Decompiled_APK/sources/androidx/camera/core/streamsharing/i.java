package androidx.camera.core.streamsharing;

import androidx.camera.core.impl.InterfaceC0183w;
import androidx.camera.core.impl.L;
import java.util.UUID;

/* loaded from: classes.dex */
public final class i extends L {
    public final String b;
    public int c;

    public i(InterfaceC0183w interfaceC0183w) {
        super(interfaceC0183w);
        this.b = "virtual-" + interfaceC0183w.c() + "-" + UUID.randomUUID().toString();
    }

    @Override // androidx.camera.core.impl.L, androidx.camera.core.impl.InterfaceC0183w
    public final int a() {
        return g(0);
    }

    @Override // androidx.camera.core.impl.L, androidx.camera.core.impl.InterfaceC0183w
    public final String c() {
        return this.b;
    }

    @Override // androidx.camera.core.impl.L, androidx.camera.core.impl.InterfaceC0183w
    public final int g(int i) {
        return androidx.camera.core.impl.utils.f.f(this.a.g(i) - this.c);
    }
}
