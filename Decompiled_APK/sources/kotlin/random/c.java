package kotlin.random;

import java.io.Serializable;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes3.dex */
public final class c implements Serializable {

    @NotNull
    public static final c a = new c();

    private final Object readResolve() {
        return e.a;
    }
}
