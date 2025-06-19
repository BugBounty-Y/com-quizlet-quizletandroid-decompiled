package androidx.recyclerview.widget;

import android.view.View;
import androidx.compose.material3.C0676l1;
import androidx.core.view.InterfaceC1053j;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;

/* renamed from: androidx.recyclerview.widget.b0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1357b0 implements InterfaceC1053j {
    public final /* synthetic */ RecyclerView a;

    public /* synthetic */ C1357b0(RecyclerView recyclerView) {
        this.a = recyclerView;
    }

    @Override // androidx.core.view.InterfaceC1053j
    public void A() {
        this.a.s0();
    }

    public void a(C1354a c1354a) {
        int i = c1354a.a;
        RecyclerView recyclerView = this.a;
        if (i == 1) {
            recyclerView.n.c0(c1354a.b, c1354a.d);
            return;
        }
        if (i == 2) {
            recyclerView.n.f0(c1354a.b, c1354a.d);
        } else if (i == 4) {
            recyclerView.n.g0(c1354a.b, c1354a.d);
        } else {
            if (i != 8) {
                return;
            }
            recyclerView.n.e0(c1354a.b, c1354a.d);
        }
    }

    public F0 b(int i) {
        RecyclerView recyclerView = this.a;
        int iC = recyclerView.f.C();
        int i2 = 0;
        F0 f0 = null;
        while (true) {
            if (i2 >= iC) {
                break;
            }
            F0 f0P = RecyclerView.P(recyclerView.f.B(i2));
            if (f0P != null && !f0P.isRemoved() && f0P.mPosition == i) {
                if (!((ArrayList) recyclerView.f.c).contains(f0P.itemView)) {
                    f0 = f0P;
                    break;
                }
                f0 = f0P;
            }
            i2++;
        }
        if (f0 == null) {
            return null;
        }
        if (!((ArrayList) recyclerView.f.c).contains(f0.itemView)) {
            return f0;
        }
        boolean z = RecyclerView.M1;
        return null;
    }

    public void c(int i, int i2, Object obj) {
        int i3;
        int i4;
        RecyclerView recyclerView = this.a;
        int iC = recyclerView.f.C();
        int i5 = i2 + i;
        for (int i6 = 0; i6 < iC; i6++) {
            View viewB = recyclerView.f.B(i6);
            F0 f0P = RecyclerView.P(viewB);
            if (f0P != null && !f0P.shouldIgnore() && (i4 = f0P.mPosition) >= i && i4 < i5) {
                f0P.addFlags(2);
                f0P.addChangePayload(obj);
                ((C1383o0) viewB.getLayoutParams()).c = true;
            }
        }
        v0 v0Var = recyclerView.c;
        ArrayList arrayList = v0Var.c;
        for (int size = arrayList.size() - 1; size >= 0; size--) {
            F0 f0 = (F0) arrayList.get(size);
            if (f0 != null && (i3 = f0.mPosition) >= i && i3 < i5) {
                f0.addFlags(2);
                v0Var.g(size);
            }
        }
        recyclerView.v1 = true;
    }

    public void d(int i, int i2) {
        RecyclerView recyclerView = this.a;
        int iC = recyclerView.f.C();
        for (int i3 = 0; i3 < iC; i3++) {
            F0 f0P = RecyclerView.P(recyclerView.f.B(i3));
            if (f0P != null && !f0P.shouldIgnore() && f0P.mPosition >= i) {
                if (RecyclerView.N1) {
                    f0P.toString();
                }
                f0P.offsetPosition(i2, false);
                recyclerView.r1.f = true;
            }
        }
        ArrayList arrayList = recyclerView.c.c;
        int size = arrayList.size();
        for (int i4 = 0; i4 < size; i4++) {
            F0 f0 = (F0) arrayList.get(i4);
            if (f0 != null && f0.mPosition >= i) {
                if (RecyclerView.N1) {
                    f0.toString();
                }
                f0.offsetPosition(i2, false);
            }
        }
        recyclerView.requestLayout();
        recyclerView.u1 = true;
    }

    public void e(int i, int i2) {
        int i3;
        int i4;
        int i5;
        int i6;
        int i7;
        int i8;
        int i9;
        RecyclerView recyclerView = this.a;
        int iC = recyclerView.f.C();
        int i10 = -1;
        if (i < i2) {
            i4 = i;
            i3 = i2;
            i5 = -1;
        } else {
            i3 = i;
            i4 = i2;
            i5 = 1;
        }
        for (int i11 = 0; i11 < iC; i11++) {
            F0 f0P = RecyclerView.P(recyclerView.f.B(i11));
            if (f0P != null && (i9 = f0P.mPosition) >= i4 && i9 <= i3) {
                if (RecyclerView.N1) {
                    f0P.toString();
                }
                if (f0P.mPosition == i) {
                    f0P.offsetPosition(i2 - i, false);
                } else {
                    f0P.offsetPosition(i5, false);
                }
                recyclerView.r1.f = true;
            }
        }
        v0 v0Var = recyclerView.c;
        v0Var.getClass();
        if (i < i2) {
            i7 = i;
            i6 = i2;
        } else {
            i6 = i;
            i7 = i2;
            i10 = 1;
        }
        ArrayList arrayList = v0Var.c;
        int size = arrayList.size();
        for (int i12 = 0; i12 < size; i12++) {
            F0 f0 = (F0) arrayList.get(i12);
            if (f0 != null && (i8 = f0.mPosition) >= i7 && i8 <= i6) {
                if (i8 == i) {
                    f0.offsetPosition(i2 - i, false);
                } else {
                    f0.offsetPosition(i10, false);
                }
                if (RecyclerView.N1) {
                    f0.toString();
                }
            }
        }
        recyclerView.requestLayout();
        recyclerView.u1 = true;
    }

    /* JADX WARN: Removed duplicated region for block: B:9:0x0020  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void f(androidx.recyclerview.widget.F0 r9, androidx.compose.material3.C0676l1 r10, androidx.compose.material3.C0676l1 r11) {
        /*
            r8 = this;
            androidx.recyclerview.widget.RecyclerView r0 = r8.a
            r0.getClass()
            r1 = 0
            r9.setIsRecyclable(r1)
            androidx.recyclerview.widget.j0 r1 = r0.M
            r2 = r1
            androidx.recyclerview.widget.q r2 = (androidx.recyclerview.widget.C1386q) r2
            if (r10 == 0) goto L20
            r2.getClass()
            int r4 = r10.a
            int r6 = r11.a
            if (r4 != r6) goto L22
            int r1 = r10.b
            int r3 = r11.b
            if (r1 == r3) goto L20
            goto L22
        L20:
            r3 = r9
            goto L2c
        L22:
            int r5 = r10.b
            int r7 = r11.b
            r3 = r9
            boolean r9 = r2.g(r3, r4, r5, r6, r7)
            goto L3b
        L2c:
            r2.l(r3)
            android.view.View r9 = r3.itemView
            r10 = 0
            r9.setAlpha(r10)
            java.util.ArrayList r9 = r2.i
            r9.add(r3)
            r9 = 1
        L3b:
            if (r9 == 0) goto L40
            r0.Z()
        L40:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.recyclerview.widget.C1357b0.f(androidx.recyclerview.widget.F0, androidx.compose.material3.l1, androidx.compose.material3.l1):void");
    }

    public void g(F0 f0, C0676l1 c0676l1, C0676l1 c0676l12) {
        boolean zG;
        RecyclerView recyclerView = this.a;
        recyclerView.c.l(f0);
        recyclerView.h(f0);
        f0.setIsRecyclable(false);
        C1386q c1386q = (C1386q) recyclerView.M;
        c1386q.getClass();
        int i = c0676l1.a;
        int i2 = c0676l1.b;
        View view = f0.itemView;
        int left = c0676l12 == null ? view.getLeft() : c0676l12.a;
        int top = c0676l12 == null ? view.getTop() : c0676l12.b;
        if (f0.isRemoved() || (i == left && i2 == top)) {
            c1386q.l(f0);
            c1386q.h.add(f0);
            zG = true;
        } else {
            view.layout(left, top, view.getWidth() + left, view.getHeight() + top);
            zG = c1386q.g(f0, i, i2, left, top);
        }
        if (zG) {
            recyclerView.Z();
        }
    }

    public void h(int i) {
        RecyclerView recyclerView = this.a;
        View childAt = recyclerView.getChildAt(i);
        if (childAt != null) {
            recyclerView.s(childAt);
            childAt.clearAnimation();
        }
        recyclerView.removeViewAt(i);
    }

    @Override // androidx.core.view.InterfaceC1053j
    public boolean k(float f) {
        int i;
        int i2;
        RecyclerView recyclerView = this.a;
        if (recyclerView.n.e()) {
            i2 = (int) f;
            i = 0;
        } else if (recyclerView.n.d()) {
            i = (int) f;
            i2 = 0;
        } else {
            i = 0;
            i2 = 0;
        }
        if (i == 0 && i2 == 0) {
            return false;
        }
        recyclerView.s0();
        return recyclerView.L(i, i2, 0, SubsamplingScaleImageView.TILE_SIZE_AUTO);
    }

    @Override // androidx.core.view.InterfaceC1053j
    public float w() {
        float f;
        RecyclerView recyclerView = this.a;
        if (recyclerView.n.e()) {
            f = recyclerView.m1;
        } else {
            if (!recyclerView.n.d()) {
                return DefinitionKt.NO_Float_VALUE;
            }
            f = recyclerView.l1;
        }
        return -f;
    }
}
