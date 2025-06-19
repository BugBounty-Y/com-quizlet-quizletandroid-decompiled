package kotlinx.serialization.internal;

/* renamed from: kotlinx.serialization.internal.m, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public abstract class AbstractC5059m {
    public static final boolean a;

    static {
        boolean z;
        try {
            Class.forName("java.lang.ClassValue");
            z = true;
        } catch (Throwable unused) {
            z = false;
        }
        a = z;
    }
}
