package androidx.viewpager2.widget;

import androidx.recyclerview.widget.AbstractC1390s0;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes.dex */
public final class d extends AbstractC1390s0 {
    public f a;
    public final ViewPager2 b;
    public final l c;
    public final LinearLayoutManager d;
    public int e;
    public int f;
    public final c g;
    public int h;
    public int i;
    public boolean j;
    public boolean k;
    public boolean l;

    public d(ViewPager2 viewPager2) {
        this.b = viewPager2;
        l lVar = viewPager2.j;
        this.c = lVar;
        this.d = (LinearLayoutManager) lVar.getLayoutManager();
        this.g = new c();
        d();
    }

    @Override // androidx.recyclerview.widget.AbstractC1390s0
    public final void a(RecyclerView recyclerView, int i) {
        f fVar;
        f fVar2;
        int i2 = this.e;
        boolean z = true;
        if (!(i2 == 1 && this.f == 1) && i == 1) {
            this.e = 1;
            int i3 = this.i;
            if (i3 != -1) {
                this.h = i3;
                this.i = -1;
            } else if (this.h == -1) {
                this.h = this.d.S0();
            }
            c(1);
            return;
        }
        if ((i2 == 1 || i2 == 4) && i == 2) {
            if (this.k) {
                c(2);
                this.j = true;
                return;
            }
            return;
        }
        if (i2 != 1 && i2 != 4) {
            z = false;
        }
        c cVar = this.g;
        if (z && i == 0) {
            e();
            if (!this.k) {
                int i4 = cVar.b;
                if (i4 != -1 && (fVar2 = this.a) != null) {
                    fVar2.b(i4, DefinitionKt.NO_Float_VALUE, 0);
                }
            } else if (cVar.c == 0) {
                int i5 = this.h;
                int i6 = cVar.b;
                if (i5 != i6 && (fVar = this.a) != null) {
                    fVar.c(i6);
                }
            }
            c(0);
            d();
        }
        if (this.e == 2 && i == 0 && this.l) {
            e();
            if (cVar.c == 0) {
                int i7 = this.i;
                int i8 = cVar.b;
                if (i7 != i8) {
                    if (i8 == -1) {
                        i8 = 0;
                    }
                    f fVar3 = this.a;
                    if (fVar3 != null) {
                        fVar3.c(i8);
                    }
                }
                c(0);
                d();
            }
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:15:0x002a  */
    @Override // androidx.recyclerview.widget.AbstractC1390s0
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void b(androidx.recyclerview.widget.RecyclerView r6, int r7, int r8) {
        /*
            r5 = this;
            r6 = 1
            r5.k = r6
            r5.e()
            boolean r0 = r5.j
            androidx.viewpager2.widget.c r1 = r5.g
            r2 = -1
            r3 = 0
            if (r0 == 0) goto L42
            r5.j = r3
            if (r8 > 0) goto L2a
            if (r8 != 0) goto L32
            if (r7 >= 0) goto L18
            r7 = r6
            goto L19
        L18:
            r7 = r3
        L19:
            androidx.viewpager2.widget.ViewPager2 r8 = r5.b
            androidx.viewpager2.widget.h r8 = r8.g
            androidx.recyclerview.widget.RecyclerView r8 = r8.b
            int r8 = r8.getLayoutDirection()
            if (r8 != r6) goto L27
            r8 = r6
            goto L28
        L27:
            r8 = r3
        L28:
            if (r7 != r8) goto L32
        L2a:
            int r7 = r1.c
            if (r7 == 0) goto L32
            int r7 = r1.b
            int r7 = r7 + r6
            goto L34
        L32:
            int r7 = r1.b
        L34:
            r5.i = r7
            int r8 = r5.h
            if (r8 == r7) goto L52
            androidx.viewpager2.widget.f r8 = r5.a
            if (r8 == 0) goto L52
            r8.c(r7)
            goto L52
        L42:
            int r7 = r5.e
            if (r7 != 0) goto L52
            int r7 = r1.b
            if (r7 != r2) goto L4b
            r7 = r3
        L4b:
            androidx.viewpager2.widget.f r8 = r5.a
            if (r8 == 0) goto L52
            r8.c(r7)
        L52:
            int r7 = r1.b
            if (r7 != r2) goto L57
            r7 = r3
        L57:
            float r8 = r1.a
            int r0 = r1.c
            androidx.viewpager2.widget.f r4 = r5.a
            if (r4 == 0) goto L62
            r4.b(r7, r8, r0)
        L62:
            int r7 = r1.b
            int r8 = r5.i
            if (r7 == r8) goto L6a
            if (r8 != r2) goto L78
        L6a:
            int r7 = r1.c
            if (r7 != 0) goto L78
            int r7 = r5.f
            if (r7 == r6) goto L78
            r5.c(r3)
            r5.d()
        L78:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.viewpager2.widget.d.b(androidx.recyclerview.widget.RecyclerView, int, int):void");
    }

    public final void c(int i) {
        if ((this.e == 3 && this.f == 0) || this.f == i) {
            return;
        }
        this.f = i;
        f fVar = this.a;
        if (fVar != null) {
            fVar.a(i);
        }
    }

    public final void d() {
        this.e = 0;
        this.f = 0;
        c cVar = this.g;
        cVar.b = -1;
        cVar.a = DefinitionKt.NO_Float_VALUE;
        cVar.c = 0;
        this.h = -1;
        this.i = -1;
        this.j = false;
        this.k = false;
        this.l = false;
    }

    /* JADX WARN: Removed duplicated region for block: B:65:0x0140  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void e() {
        /*
            Method dump skipped, instructions count: 367
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.viewpager2.widget.d.e():void");
    }
}
