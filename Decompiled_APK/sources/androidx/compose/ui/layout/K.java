package androidx.compose.ui.layout;

import com.google.android.gms.internal.mlkit_vision_barcode.L5;
import java.util.ArrayList;
import java.util.List;

/* loaded from: classes.dex */
public interface K {
    default int maxIntrinsicHeight(InterfaceC0894o interfaceC0894o, List list, int i) {
        ArrayList arrayList = new ArrayList(list.size());
        int size = list.size();
        for (int i2 = 0; i2 < size; i2++) {
            int i3 = 2;
            arrayList.add(new C0890k((J) list.get(i2), i3, i3, 0));
        }
        return mo1measure3p2s80s(new C0896q(interfaceC0894o, interfaceC0894o.getLayoutDirection()), arrayList, L5.b(i, 0, 13)).b();
    }

    default int maxIntrinsicWidth(InterfaceC0894o interfaceC0894o, List list, int i) {
        ArrayList arrayList = new ArrayList(list.size());
        int size = list.size();
        for (int i2 = 0; i2 < size; i2++) {
            arrayList.add(new C0890k((J) list.get(i2), 2, 1, 0));
        }
        return mo1measure3p2s80s(new C0896q(interfaceC0894o, interfaceC0894o.getLayoutDirection()), arrayList, L5.b(0, i, 7)).getWidth();
    }

    /* renamed from: measure-3p2s80s */
    L mo1measure3p2s80s(M m, List list, long j);

    default int minIntrinsicHeight(InterfaceC0894o interfaceC0894o, List list, int i) {
        ArrayList arrayList = new ArrayList(list.size());
        int size = list.size();
        for (int i2 = 0; i2 < size; i2++) {
            arrayList.add(new C0890k((J) list.get(i2), 1, 2, 0));
        }
        return mo1measure3p2s80s(new C0896q(interfaceC0894o, interfaceC0894o.getLayoutDirection()), arrayList, L5.b(i, 0, 13)).b();
    }

    default int minIntrinsicWidth(InterfaceC0894o interfaceC0894o, List list, int i) {
        ArrayList arrayList = new ArrayList(list.size());
        int size = list.size();
        for (int i2 = 0; i2 < size; i2++) {
            int i3 = 1;
            arrayList.add(new C0890k((J) list.get(i2), i3, i3, 0));
        }
        return mo1measure3p2s80s(new C0896q(interfaceC0894o, interfaceC0894o.getLayoutDirection()), arrayList, L5.b(0, i, 7)).getWidth();
    }
}
