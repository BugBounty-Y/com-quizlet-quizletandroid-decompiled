package coil3.request;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes.dex */
public final class b {
    public static final b c;
    public static final /* synthetic */ b[] d;
    public final boolean a;
    public final boolean b;

    static {
        b bVar = new b(true, true, "ENABLED", 0);
        c = bVar;
        b[] bVarArr = {bVar, new b(true, false, "READ_ONLY", 1), new b(false, true, "WRITE_ONLY", 2), new b(false, false, "DISABLED", 3)};
        d = bVarArr;
        AbstractC3328d.f(bVarArr);
    }

    public b(boolean z, boolean z2, String str, int i) {
        this.a = z;
        this.b = z2;
    }

    public static b valueOf(String str) {
        return (b) Enum.valueOf(b.class, str);
    }

    public static b[] values() {
        return (b[]) d.clone();
    }
}
