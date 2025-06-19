package kotlinx.coroutines.rx3;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class a {
    public static final a b;
    public static final /* synthetic */ a[] c;
    public final String a;

    static {
        a aVar = new a("FIRST", 0, "awaitFirst");
        b = aVar;
        a[] aVarArr = {aVar, new a("FIRST_OR_DEFAULT", 1, "awaitFirstOrDefault"), new a("LAST", 2, "awaitLast"), new a("SINGLE", 3, "awaitSingle")};
        c = aVarArr;
        AbstractC3328d.f(aVarArr);
    }

    public a(String str, int i, String str2) {
        this.a = str2;
    }

    public static a valueOf(String str) {
        return (a) Enum.valueOf(a.class, str);
    }

    public static a[] values() {
        return (a[]) c.clone();
    }

    @Override // java.lang.Enum
    public final String toString() {
        return this.a;
    }
}
