package androidx.constraintlayout.core.state;

import androidx.compose.ui.node.B;
import com.comscore.android.id.IdHelperAndroid;
import java.util.HashMap;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes.dex */
public final class j {
    public static final HashMap a;
    public static final /* synthetic */ j[] b;

    /* JADX INFO: Fake field, exist only in values array */
    j EF0;

    static {
        j jVar = new j("NONE", 0);
        j jVar2 = new j("CHAIN", 1);
        j jVar3 = new j("ALIGNED", 2);
        b = new j[]{jVar, jVar2, jVar3};
        HashMap map = new HashMap();
        HashMap map2 = new HashMap();
        a = map2;
        map.put(IdHelperAndroid.NO_ID_AVAILABLE, jVar);
        map.put("chain", jVar2);
        map.put("aligned", jVar3);
        B.r(0, map2, IdHelperAndroid.NO_ID_AVAILABLE, 3, "chain");
        map2.put("aligned", 2);
    }

    public static j valueOf(String str) {
        return (j) Enum.valueOf(j.class, str);
    }

    public static j[] values() {
        return (j[]) b.clone();
    }
}
