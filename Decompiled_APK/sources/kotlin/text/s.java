package kotlin.text;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import kotlin.jvm.internal.DefaultConstructorMarker;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class s implements InterfaceC4965d {
    public static final s b;
    public static final s c;
    public static final /* synthetic */ s[] d;
    public final int a;

    static {
        s sVar = new s("IGNORE_CASE", 0, 2, 0, 2, null);
        b = sVar;
        s sVar2 = new s("MULTILINE", 1, 8, 0, 2, null);
        s sVar3 = new s("LITERAL", 2, 16, 0, 2, null);
        s sVar4 = new s("UNIX_LINES", 3, 1, 0, 2, null);
        s sVar5 = new s("COMMENTS", 4, 4, 0, 2, null);
        s sVar6 = new s("DOT_MATCHES_ALL", 5, 32, 0, 2, null);
        c = sVar6;
        s[] sVarArr = {sVar, sVar2, sVar3, sVar4, sVar5, sVar6, new s("CANON_EQ", 6, 128, 0, 2, null)};
        d = sVarArr;
        AbstractC3328d.f(sVarArr);
    }

    public s(String str, int i, int i2, int i3, int i4, DefaultConstructorMarker defaultConstructorMarker) {
        this.a = i2;
    }

    public static s valueOf(String str) {
        return (s) Enum.valueOf(s.class, str);
    }

    public static s[] values() {
        return (s[]) d.clone();
    }
}
