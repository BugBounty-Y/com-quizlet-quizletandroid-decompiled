package androidx.glance.semantics;

import java.util.ArrayList;
import java.util.List;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.r;

/* loaded from: classes.dex */
public final class c extends r implements Function2 {
    public static final c b = new c(2, 0);
    public static final c c = new c(2, 1);
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ c(int i, int i2) {
        super(i);
        this.a = i2;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                List list = (List) obj;
                List list2 = (List) obj2;
                if (list == null) {
                    return list2;
                }
                ArrayList arrayListY0 = CollectionsKt.y0(list);
                arrayListY0.addAll(list2);
                return arrayListY0;
            default:
                return (String) obj;
        }
    }
}
