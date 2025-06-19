package androidx.compose.foundation.pager;

import androidx.compose.ui.node.V;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.Regex;

/* renamed from: androidx.compose.foundation.pager.c, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0464c extends kotlin.jvm.internal.r implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ List b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C0464c(List list, int i) {
        super(0);
        this.a = i;
        this.b = list;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                Object obj = this.b.get(2);
                Intrinsics.e(obj, "null cannot be cast to non-null type kotlin.Int");
                return (Integer) obj;
            case 1:
                List list = this.b;
                ArrayList arrayList = new ArrayList(kotlin.collections.C.q(list, 10));
                Iterator it2 = list.iterator();
                while (it2.hasNext()) {
                    arrayList.add(((Regex) assistantMode.utils.classification.e.a.getValue()).replace((String) it2.next(), ""));
                }
                return arrayList;
            default:
                return this.b;
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0464c(List list, V v) {
        super(0);
        this.a = 1;
        this.b = list;
    }
}
