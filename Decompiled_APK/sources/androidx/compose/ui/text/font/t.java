package androidx.compose.ui.text.font;

import androidx.compose.animation.d0;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class t {
    public final ArrayList a;

    public t(s... sVarArr) {
        LinkedHashMap linkedHashMap = new LinkedHashMap();
        if (sVarArr.length > 0) {
            s sVar = sVarArr[0];
            throw null;
        }
        ArrayList arrayList = new ArrayList();
        for (Map.Entry entry : linkedHashMap.entrySet()) {
            String str = (String) entry.getKey();
            List list = (List) entry.getValue();
            if (list.size() != 1) {
                throw new IllegalArgumentException(d0.r(android.support.v4.media.session.a.y("'", str, "' must be unique. Actual [ ["), CollectionsKt.S(list, null, null, null, null, 63), ']').toString());
            }
            kotlin.collections.G.u(arrayList, list);
        }
        ArrayList arrayList2 = new ArrayList(arrayList);
        this.a = arrayList2;
        if (arrayList2.size() <= 0) {
            return;
        }
        arrayList2.get(0).getClass();
        throw new ClassCastException();
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof t) && Intrinsics.b(this.a, ((t) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }
}
