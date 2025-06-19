package androidx.constraintlayout.core.state;

import androidx.compose.ui.node.B;
import java.util.HashMap;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes.dex */
public final class i {
    public static final i a;
    public static final i b;
    public static final i c;
    public static final HashMap d;
    public static final /* synthetic */ i[] e;

    static {
        i iVar = new i("SPREAD", 0);
        a = iVar;
        i iVar2 = new i("SPREAD_INSIDE", 1);
        b = iVar2;
        i iVar3 = new i("PACKED", 2);
        c = iVar3;
        e = new i[]{iVar, iVar2, iVar3};
        HashMap map = new HashMap();
        HashMap map2 = new HashMap();
        d = map2;
        map.put("packed", iVar3);
        map.put("spread_inside", iVar2);
        map.put("spread", iVar);
        B.r(2, map2, "packed", 1, "spread_inside");
        map2.put("spread", 0);
    }

    public static int a(String str) {
        HashMap map = d;
        if (map.containsKey(str)) {
            return ((Integer) map.get(str)).intValue();
        }
        return -1;
    }

    public static i valueOf(String str) {
        return (i) Enum.valueOf(i.class, str);
    }

    public static i[] values() {
        return (i[]) e.clone();
    }
}
