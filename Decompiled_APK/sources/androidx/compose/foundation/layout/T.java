package androidx.compose.foundation.layout;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class T {
    public boolean a;
    public long b;
    public final Object c;
    public Object d;

    public T(androidx.compose.ui.layout.J j, androidx.compose.ui.layout.W w, long j2) {
        this.c = j;
        this.d = w;
        this.b = j2;
        this.a = true;
    }

    public boolean a() {
        Boolean bool = (Boolean) this.d;
        return bool != null ? bool.booleanValue() : this.a;
    }

    public T(boolean z, String key) {
        Intrinsics.checkNotNullParameter(key, "key");
        this.a = z;
        this.c = key;
    }
}
