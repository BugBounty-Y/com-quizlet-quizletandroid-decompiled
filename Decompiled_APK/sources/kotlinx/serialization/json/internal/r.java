package kotlinx.serialization.json.internal;

import java.util.LinkedHashMap;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class r extends n {
    public String i;
    public boolean j;

    @Override // kotlinx.serialization.json.internal.n
    public final kotlinx.serialization.json.k J() {
        return new kotlinx.serialization.json.v((LinkedHashMap) this.h);
    }

    @Override // kotlinx.serialization.json.internal.n
    public final void M(String key, kotlinx.serialization.json.k element) {
        Intrinsics.checkNotNullParameter(key, "key");
        Intrinsics.checkNotNullParameter(element, "element");
        if (!this.j) {
            LinkedHashMap linkedHashMap = (LinkedHashMap) this.h;
            String str = this.i;
            if (str == null) {
                Intrinsics.m("tag");
                throw null;
            }
            linkedHashMap.put(str, element);
            this.j = true;
            return;
        }
        if (element instanceof kotlinx.serialization.json.y) {
            this.i = ((kotlinx.serialization.json.y) element).a();
            this.j = false;
        } else {
            if (element instanceof kotlinx.serialization.json.v) {
                throw k.b(kotlinx.serialization.json.x.b);
            }
            if (!(element instanceof kotlinx.serialization.json.d)) {
                throw new NoWhenBranchMatchedException();
            }
            throw k.b(kotlinx.serialization.json.f.b);
        }
    }
}
