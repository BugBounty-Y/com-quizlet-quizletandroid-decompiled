package androidx.compose.runtime.external.kotlinx.collections.immutable;

import com.google.android.gms.internal.mlkit_vision_barcode.I4;
import java.util.List;
import kotlin.collections.AbstractC4916g;

/* loaded from: classes.dex */
public final class a extends AbstractC4916g {
    public final androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableList.c b;
    public final int c;
    public final int d;

    public a(androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableList.c cVar, int i, int i2) {
        this.b = cVar;
        this.c = i;
        I4.d(i, i2, cVar.size());
        this.d = i2 - i;
    }

    @Override // kotlin.collections.AbstractC4911b
    public final int a() {
        return this.d;
    }

    @Override // java.util.List
    public final Object get(int i) {
        I4.b(i, this.d);
        return this.b.get(this.c + i);
    }

    @Override // kotlin.collections.AbstractC4916g, java.util.List
    public final List subList(int i, int i2) {
        I4.d(i, i2, this.d);
        int i3 = this.c;
        return new a(this.b, i + i3, i3 + i2);
    }
}
