package kotlinx.collections.immutable;

import com.google.android.gms.internal.mlkit_vision_camera.A1;
import java.util.List;
import kotlin.collections.AbstractC4916g;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a extends AbstractC4916g implements b {
    public final kotlinx.collections.immutable.implementations.immutableList.a b;
    public final int c;
    public final int d;

    public a(kotlinx.collections.immutable.implementations.immutableList.a source, int i, int i2) {
        Intrinsics.checkNotNullParameter(source, "source");
        this.b = source;
        this.c = i;
        A1.g(i, i2, source.size());
        this.d = i2 - i;
    }

    @Override // kotlin.collections.AbstractC4911b
    public final int a() {
        return this.d;
    }

    @Override // java.util.List
    public final Object get(int i) {
        A1.e(i, this.d);
        return this.b.get(this.c + i);
    }

    @Override // kotlin.collections.AbstractC4916g, java.util.List
    public final List subList(int i, int i2) {
        A1.g(i, i2, this.d);
        int i3 = this.c;
        return new a(this.b, i + i3, i3 + i2);
    }
}
