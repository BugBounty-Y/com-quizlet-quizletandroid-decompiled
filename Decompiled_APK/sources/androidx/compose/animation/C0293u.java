package androidx.compose.animation;

import java.util.ArrayList;
import kotlin.jvm.functions.Function1;

/* renamed from: androidx.compose.animation.u, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0293u extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ ArrayList b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C0293u(int i, ArrayList arrayList) {
        super(1);
        this.a = i;
        this.b = arrayList;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                androidx.compose.ui.layout.V v = (androidx.compose.ui.layout.V) obj;
                ArrayList arrayList = this.b;
                int size = arrayList.size();
                for (int i = 0; i < size; i++) {
                    androidx.compose.ui.layout.V.d(v, (androidx.compose.ui.layout.W) arrayList.get(i), 0, 0);
                }
                break;
            case 1:
                androidx.compose.ui.layout.V v2 = (androidx.compose.ui.layout.V) obj;
                ArrayList arrayList2 = this.b;
                int size2 = arrayList2.size();
                for (int i2 = 0; i2 < size2; i2++) {
                    androidx.compose.ui.layout.V.f(v2, (androidx.compose.ui.layout.W) arrayList2.get(i2), 0, 0);
                }
                break;
            case 2:
                androidx.compose.ui.layout.V v3 = (androidx.compose.ui.layout.V) obj;
                ArrayList arrayList3 = this.b;
                int size3 = arrayList3.size();
                for (int i3 = 0; i3 < size3; i3++) {
                    androidx.compose.ui.layout.V.d(v3, (androidx.compose.ui.layout.W) arrayList3.get(i3), 0, 0);
                }
                break;
            case 3:
                androidx.compose.ui.layout.V v4 = (androidx.compose.ui.layout.V) obj;
                ArrayList arrayList4 = this.b;
                int size4 = arrayList4.size();
                for (int i4 = 0; i4 < size4; i4++) {
                    androidx.compose.ui.layout.V.g(v4, (androidx.compose.ui.layout.W) arrayList4.get(i4), 0, 0);
                }
                break;
            case 4:
                androidx.compose.ui.layout.V v5 = (androidx.compose.ui.layout.V) obj;
                ArrayList arrayList5 = this.b;
                int size5 = arrayList5.size();
                for (int i5 = 0; i5 < size5; i5++) {
                    androidx.compose.ui.layout.V.f(v5, (androidx.compose.ui.layout.W) arrayList5.get(i5), 0, 0);
                }
                break;
            case 5:
                androidx.compose.ui.layout.V v6 = (androidx.compose.ui.layout.V) obj;
                ArrayList arrayList6 = this.b;
                int i6 = kotlin.collections.B.i(arrayList6);
                if (i6 >= 0) {
                    int i7 = 0;
                    while (true) {
                        androidx.compose.ui.layout.V.f(v6, (androidx.compose.ui.layout.W) arrayList6.get(i7), 0, 0);
                        if (i7 != i6) {
                            i7++;
                        }
                    }
                }
                break;
            case 6:
                this.b.get(((Number) obj).intValue());
                break;
            case 7:
                this.b.get(((Number) obj).intValue());
                break;
            case 8:
                this.b.get(((Number) obj).intValue());
                break;
            default:
                this.b.get(((Number) obj).intValue());
                break;
        }
        return null;
    }
}
