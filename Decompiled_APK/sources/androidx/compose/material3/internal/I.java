package androidx.compose.material3.internal;

import java.util.LinkedHashMap;
import kotlinx.coroutines.flow.InterfaceC4992i;

/* loaded from: classes.dex */
public final class I implements androidx.compose.foundation.interaction.k {
    public final long a;
    public final LinkedHashMap b = new LinkedHashMap();
    public final H c;

    public I(androidx.compose.foundation.interaction.l lVar, long j) {
        this.a = j;
        this.c = new H(0, lVar.b(), this);
    }

    @Override // androidx.compose.foundation.interaction.k
    public final InterfaceC4992i b() {
        return this.c;
    }
}
