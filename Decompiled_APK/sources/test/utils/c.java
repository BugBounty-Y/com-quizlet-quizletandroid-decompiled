package test.utils;

import java.util.Comparator;
import java.util.List;
import java.util.Map;

/* loaded from: classes3.dex */
public final class c implements Comparator {
    public final /* synthetic */ int a;
    public final /* synthetic */ List b;

    public /* synthetic */ c(List list, int i) {
        this.a = i;
        this.b = list;
    }

    @Override // java.util.Comparator
    public final int compare(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                assistantMode.enums.k kVar = (assistantMode.enums.k) ((Map.Entry) obj).getKey();
                List list = this.b;
                return kotlin.comparisons.a.b(Integer.valueOf(list.indexOf(kVar)), Integer.valueOf(list.indexOf((assistantMode.enums.k) ((Map.Entry) obj2).getKey())));
            default:
                List list2 = this.b;
                return kotlin.comparisons.a.b(Integer.valueOf(list2.indexOf((assistantMode.enums.k) obj)), Integer.valueOf(list2.indexOf((assistantMode.enums.k) obj2)));
        }
    }
}
