package androidx.collection;

import androidx.recyclerview.widget.AbstractC1381n0;
import androidx.recyclerview.widget.RecyclerView;
import java.util.Arrays;
import kotlin.collections.C4930v;

/* renamed from: androidx.collection.h, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0210h {
    public int a;
    public int b;
    public int[] c;
    public int d;

    public C0210h() {
        int iHighestOneBit = Integer.bitCount(8) != 1 ? Integer.highestOneBit(7) << 1 : 8;
        this.d = iHighestOneBit - 1;
        this.c = new int[iHighestOneBit];
    }

    public void a(int i) {
        int[] iArr = this.c;
        int i2 = this.b;
        iArr[i2] = i;
        int i3 = this.d & (i2 + 1);
        this.b = i3;
        int i4 = this.a;
        if (i3 == i4) {
            int length = iArr.length;
            int i5 = length - i4;
            int i6 = length << 1;
            if (i6 < 0) {
                throw new RuntimeException("Max array capacity exceeded");
            }
            int[] iArr2 = new int[i6];
            C4930v.e(0, i4, length, iArr, iArr2);
            C4930v.e(i5, 0, this.a, this.c, iArr2);
            this.c = iArr2;
            this.a = 0;
            this.b = length;
            this.d = i6 - 1;
        }
    }

    public void b(int i, int i2) {
        if (i < 0) {
            throw new IllegalArgumentException("Layout positions must be non-negative");
        }
        if (i2 < 0) {
            throw new IllegalArgumentException("Pixel distance must be non-negative");
        }
        int i3 = this.d;
        int i4 = i3 * 2;
        int[] iArr = this.c;
        if (iArr == null) {
            int[] iArr2 = new int[4];
            this.c = iArr2;
            Arrays.fill(iArr2, -1);
        } else if (i4 >= iArr.length) {
            int[] iArr3 = new int[i3 * 4];
            this.c = iArr3;
            System.arraycopy(iArr, 0, iArr3, 0, iArr.length);
        }
        int[] iArr4 = this.c;
        iArr4[i4] = i;
        iArr4[i4 + 1] = i2;
        this.d++;
    }

    public void c(RecyclerView recyclerView, boolean z) {
        this.d = 0;
        int[] iArr = this.c;
        if (iArr != null) {
            Arrays.fill(iArr, -1);
        }
        AbstractC1381n0 abstractC1381n0 = recyclerView.n;
        if (recyclerView.m == null || abstractC1381n0 == null || !abstractC1381n0.i) {
            return;
        }
        if (z) {
            if (!recyclerView.e.h()) {
                abstractC1381n0.i(recyclerView.m.getItemCount(), this);
            }
        } else if (!recyclerView.R()) {
            abstractC1381n0.h(this.a, this.b, recyclerView.r1, this);
        }
        int i = this.d;
        if (i > abstractC1381n0.j) {
            abstractC1381n0.j = i;
            abstractC1381n0.k = z;
            recyclerView.c.m();
        }
    }
}
