package coil3;

import java.util.ArrayList;
import java.util.List;
import kotlin.collections.G;
import kotlin.collections.K;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final class d {
    public final List a;
    public final List b;
    public final List c;
    public List d;
    public List e;
    public final kotlin.u f;
    public final kotlin.u g;

    public d(List list, List list2, List list3, List list4, List list5) {
        this.a = list;
        this.b = list2;
        this.c = list3;
        this.d = list4;
        this.e = list5;
        final int i = 0;
        this.f = kotlin.l.b(new Function0(this) { // from class: coil3.b
            public final /* synthetic */ d b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                switch (i) {
                    case 0:
                        d dVar = this.b;
                        List list6 = dVar.d;
                        ArrayList arrayList = new ArrayList();
                        int size = list6.size();
                        for (int i2 = 0; i2 < size; i2++) {
                            G.u(arrayList, (List) ((Function0) list6.get(i2)).invoke());
                        }
                        dVar.d = K.a;
                        return arrayList;
                    default:
                        d dVar2 = this.b;
                        List list7 = dVar2.e;
                        ArrayList arrayList2 = new ArrayList();
                        int size2 = list7.size();
                        for (int i3 = 0; i3 < size2; i3++) {
                            G.u(arrayList2, (List) ((Function0) list7.get(i3)).invoke());
                        }
                        dVar2.e = K.a;
                        return arrayList2;
                }
            }
        });
        final int i2 = 1;
        this.g = kotlin.l.b(new Function0(this) { // from class: coil3.b
            public final /* synthetic */ d b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                switch (i2) {
                    case 0:
                        d dVar = this.b;
                        List list6 = dVar.d;
                        ArrayList arrayList = new ArrayList();
                        int size = list6.size();
                        for (int i22 = 0; i22 < size; i22++) {
                            G.u(arrayList, (List) ((Function0) list6.get(i22)).invoke());
                        }
                        dVar.d = K.a;
                        return arrayList;
                    default:
                        d dVar2 = this.b;
                        List list7 = dVar2.e;
                        ArrayList arrayList2 = new ArrayList();
                        int size2 = list7.size();
                        for (int i3 = 0; i3 < size2; i3++) {
                            G.u(arrayList2, (List) ((Function0) list7.get(i3)).invoke());
                        }
                        dVar2.e = K.a;
                        return arrayList2;
                }
            }
        });
    }
}
