package androidx.core.os;

import android.os.Bundle;
import android.util.Size;
import android.util.SizeF;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public final class a {

    @NotNull
    public static final a a = new a();

    private a() {
    }

    public static final void a(@NotNull Bundle bundle, @NotNull String str, Size size) {
        bundle.putSize(str, size);
    }

    public static final void b(@NotNull Bundle bundle, @NotNull String str, SizeF sizeF) {
        bundle.putSizeF(str, sizeF);
    }
}
