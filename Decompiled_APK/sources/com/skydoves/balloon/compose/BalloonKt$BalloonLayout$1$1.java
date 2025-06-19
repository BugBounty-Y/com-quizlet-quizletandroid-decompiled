package com.skydoves.balloon.compose;

import androidx.compose.ui.layout.InterfaceC0894o;
import androidx.compose.ui.layout.J;
import androidx.compose.ui.layout.K;
import androidx.compose.ui.layout.L;
import androidx.compose.ui.layout.M;
import androidx.compose.ui.layout.V;
import androidx.compose.ui.layout.W;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.NoSuchElementException;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.collections.C;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class BalloonKt$BalloonLayout$1$1 implements K {
    public static final BalloonKt$BalloonLayout$1$1 INSTANCE = new BalloonKt$BalloonLayout$1$1();

    /* JADX INFO: Access modifiers changed from: private */
    public static final Unit measure_3p2s80s$lambda$4(List list, V layout) {
        Intrinsics.checkNotNullParameter(layout, "$this$layout");
        Iterator it2 = list.iterator();
        while (it2.hasNext()) {
            V.d(layout, (W) it2.next(), 0, 0);
        }
        return Unit.a;
    }

    @Override // androidx.compose.ui.layout.K
    public /* bridge */ /* synthetic */ int maxIntrinsicHeight(@NotNull InterfaceC0894o interfaceC0894o, @NotNull List list, int i) {
        return super.maxIntrinsicHeight(interfaceC0894o, list, i);
    }

    @Override // androidx.compose.ui.layout.K
    public /* bridge */ /* synthetic */ int maxIntrinsicWidth(@NotNull InterfaceC0894o interfaceC0894o, @NotNull List list, int i) {
        return super.maxIntrinsicWidth(interfaceC0894o, list, i);
    }

    @Override // androidx.compose.ui.layout.K
    /* renamed from: measure-3p2s80s */
    public final L mo1measure3p2s80s(M Layout, List<? extends J> measurables, long j) {
        Intrinsics.checkNotNullParameter(Layout, "$this$Layout");
        Intrinsics.checkNotNullParameter(measurables, "measurables");
        long jA = androidx.compose.ui.unit.a.a(j, 0, 0, 0, 0, 10);
        ArrayList arrayList = new ArrayList(C.q(measurables, 10));
        Iterator<T> it2 = measurables.iterator();
        while (it2.hasNext()) {
            arrayList.add(((J) it2.next()).B(jA));
        }
        Iterator it3 = arrayList.iterator();
        if (!it3.hasNext()) {
            throw new NoSuchElementException();
        }
        int i = ((W) it3.next()).a;
        while (it3.hasNext()) {
            int i2 = ((W) it3.next()).a;
            if (i < i2) {
                i = i2;
            }
        }
        int iMax = Integer.max(i, androidx.compose.ui.unit.a.j(j));
        Iterator it4 = arrayList.iterator();
        if (!it4.hasNext()) {
            throw new NoSuchElementException();
        }
        int i3 = ((W) it4.next()).b;
        while (it4.hasNext()) {
            int i4 = ((W) it4.next()).b;
            if (i3 < i4) {
                i3 = i4;
            }
        }
        return Layout.n0(iMax, Integer.max(i3, androidx.compose.ui.unit.a.i(j)), kotlin.collections.V.c(), new d(arrayList, 2));
    }

    @Override // androidx.compose.ui.layout.K
    public /* bridge */ /* synthetic */ int minIntrinsicHeight(@NotNull InterfaceC0894o interfaceC0894o, @NotNull List list, int i) {
        return super.minIntrinsicHeight(interfaceC0894o, list, i);
    }

    @Override // androidx.compose.ui.layout.K
    public /* bridge */ /* synthetic */ int minIntrinsicWidth(@NotNull InterfaceC0894o interfaceC0894o, @NotNull List list, int i) {
        return super.minIntrinsicWidth(interfaceC0894o, list, i);
    }
}
