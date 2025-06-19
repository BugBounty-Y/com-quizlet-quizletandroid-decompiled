package androidx.compose.ui.focus;

import kotlin.NoWhenBranchMatchedException;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes.dex */
public final class s {
    public static final s a;
    public static final s b;
    public static final s c;
    public static final /* synthetic */ s[] d;

    static {
        s sVar = new s("Active", 0);
        a = sVar;
        s sVar2 = new s("ActiveParent", 1);
        b = sVar2;
        s sVar3 = new s("Captured", 2);
        s sVar4 = new s("Inactive", 3);
        c = sVar4;
        d = new s[]{sVar, sVar2, sVar3, sVar4};
    }

    public static s valueOf(String str) {
        return (s) Enum.valueOf(s.class, str);
    }

    public static s[] values() {
        return (s[]) d.clone();
    }

    public final boolean a() {
        int iOrdinal = ordinal();
        if (iOrdinal != 0) {
            if (iOrdinal == 1) {
                return false;
            }
            if (iOrdinal != 2) {
                if (iOrdinal == 3) {
                    return false;
                }
                throw new NoWhenBranchMatchedException();
            }
        }
        return true;
    }
}
