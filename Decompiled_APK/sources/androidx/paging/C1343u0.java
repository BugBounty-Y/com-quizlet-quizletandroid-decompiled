package androidx.paging;

import androidx.compose.material3.C0676l1;
import com.google.android.gms.internal.mlkit_vision_camera.D1;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import kotlin.NoWhenBranchMatchedException;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.paging.u0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1343u0 {
    public final C0676l1 a;
    public final ArrayList b;
    public final ArrayList c;
    public int d;
    public int e;
    public int f;
    public final kotlinx.coroutines.channels.h g;
    public final kotlinx.coroutines.channels.h h;
    public final LinkedHashMap i;
    public final io.ktor.client.plugins.api.d j;

    public C1343u0(C0676l1 c0676l1) {
        this.a = c0676l1;
        ArrayList arrayList = new ArrayList();
        this.b = arrayList;
        this.c = arrayList;
        this.g = D1.a(-1, 6, null);
        this.h = D1.a(-1, 6, null);
        this.i = new LinkedHashMap();
        io.ktor.client.plugins.api.d dVar = new io.ktor.client.plugins.api.d(3);
        dVar.z(G.a, C.b);
        this.j = dVar;
    }

    public final T0 a(i1 i1Var) {
        Integer numValueOf;
        int size;
        int i;
        ArrayList arrayList = this.c;
        List listW0 = CollectionsKt.w0(arrayList);
        C0676l1 c0676l1 = this.a;
        if (i1Var != null) {
            int i2 = this.e;
            int i3 = -this.d;
            int i4 = kotlin.collections.B.i(arrayList) - this.d;
            int i5 = i3;
            while (true) {
                size = c0676l1.a;
                i = i1Var.e;
                if (i5 >= i) {
                    break;
                }
                if (i5 <= i4) {
                    size = ((P0) arrayList.get(this.d + i5)).a.size();
                }
                i2 += size;
                i5++;
            }
            int i6 = i2 + i1Var.f;
            if (i < i3) {
                i6 -= size;
            }
            numValueOf = Integer.valueOf(i6);
        } else {
            numValueOf = null;
        }
        return new T0(listW0, numValueOf, c0676l1, this.e);
    }

    public final boolean b(int i, G loadType, P0 page) {
        Intrinsics.checkNotNullParameter(loadType, "loadType");
        Intrinsics.checkNotNullParameter(page, "page");
        int iOrdinal = loadType.ordinal();
        ArrayList arrayList = this.b;
        ArrayList arrayList2 = this.c;
        if (iOrdinal == 0) {
            if (!arrayList2.isEmpty()) {
                throw new IllegalStateException("cannot receive multiple init calls");
            }
            if (i != 0) {
                throw new IllegalStateException("init loadId must be the initial value, 0");
            }
            arrayList.add(page);
            this.d = 0;
            int i2 = page.e;
            if (i2 == Integer.MIN_VALUE) {
                i2 = 0;
            }
            this.f = i2;
            int i3 = page.d;
            this.e = i3 != Integer.MIN_VALUE ? i3 : 0;
            return true;
        }
        LinkedHashMap linkedHashMap = this.i;
        if (iOrdinal != 1) {
            if (iOrdinal != 2) {
                return true;
            }
            if (arrayList2.isEmpty()) {
                throw new IllegalStateException("should've received an init before append");
            }
            if (i == 0) {
                arrayList.add(page);
                int size = page.e;
                if (size == Integer.MIN_VALUE && (size = this.f - page.a.size()) < 0) {
                    size = 0;
                }
                this.f = size != Integer.MIN_VALUE ? size : 0;
                linkedHashMap.remove(G.c);
                return true;
            }
        } else {
            if (arrayList2.isEmpty()) {
                throw new IllegalStateException("should've received an init before prepend");
            }
            if (i == 0) {
                arrayList.add(0, page);
                this.d++;
                int size2 = page.d;
                if (size2 == Integer.MIN_VALUE && (size2 = this.e - page.a.size()) < 0) {
                    size2 = 0;
                }
                this.e = size2 != Integer.MIN_VALUE ? size2 : 0;
                linkedHashMap.remove(G.b);
                return true;
            }
        }
        return false;
    }

    public final L c(P0 p0, G loadType) {
        Intrinsics.checkNotNullParameter(p0, "<this>");
        Intrinsics.checkNotNullParameter(loadType, "loadType");
        int iOrdinal = loadType.ordinal();
        int size = 0;
        if (iOrdinal != 0) {
            if (iOrdinal == 1) {
                size = 0 - this.d;
            } else {
                if (iOrdinal != 2) {
                    throw new NoWhenBranchMatchedException();
                }
                size = (this.c.size() - this.d) - 1;
            }
        }
        List pages = kotlin.collections.A.b(new g1(size, p0.a));
        int iOrdinal2 = loadType.ordinal();
        io.ktor.client.plugins.api.d dVar = this.j;
        if (iOrdinal2 == 0) {
            L l = L.g;
            return AbstractC1348x.a(pages, this.e, this.f, dVar.B(), null);
        }
        if (iOrdinal2 == 1) {
            L l2 = L.g;
            int i = this.e;
            F sourceLoadStates = dVar.B();
            Intrinsics.checkNotNullParameter(pages, "pages");
            Intrinsics.checkNotNullParameter(sourceLoadStates, "sourceLoadStates");
            return new L(G.b, pages, i, -1, sourceLoadStates, null);
        }
        if (iOrdinal2 != 2) {
            throw new NoWhenBranchMatchedException();
        }
        L l3 = L.g;
        int i2 = this.f;
        F sourceLoadStates2 = dVar.B();
        Intrinsics.checkNotNullParameter(pages, "pages");
        Intrinsics.checkNotNullParameter(sourceLoadStates2, "sourceLoadStates");
        return new L(G.c, pages, -1, i2, sourceLoadStates2, null);
    }
}
