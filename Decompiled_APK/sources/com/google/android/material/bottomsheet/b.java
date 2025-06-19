package com.google.android.material.bottomsheet;

import android.view.View;
import android.view.ViewGroup;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3188k6;
import com.google.android.gms.internal.mlkit_vision_barcode.I6;
import com.google.android.material.sidesheet.SideSheetBehavior;
import java.lang.ref.WeakReference;
import java.util.Iterator;
import java.util.LinkedHashSet;

/* loaded from: classes2.dex */
public final class b extends I6 {
    public final /* synthetic */ int a;
    public final /* synthetic */ androidx.coordinatorlayout.widget.b b;

    public /* synthetic */ b(androidx.coordinatorlayout.widget.b bVar, int i) {
        this.a = i;
        this.b = bVar;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_barcode.I6
    public final int b(int i, View view) {
        int iA;
        int i2;
        switch (this.a) {
            case 0:
                return view.getLeft();
            default:
                SideSheetBehavior sideSheetBehavior = (SideSheetBehavior) this.b;
                com.google.android.material.sidesheet.a aVar = sideSheetBehavior.a;
                switch (aVar.a) {
                    case 0:
                        iA = -aVar.b.l;
                        break;
                    default:
                        iA = aVar.a();
                        break;
                }
                com.google.android.material.sidesheet.a aVar2 = sideSheetBehavior.a;
                switch (aVar2.a) {
                    case 0:
                        i2 = aVar2.b.o;
                        break;
                    default:
                        i2 = aVar2.b.m;
                        break;
                }
                return AbstractC3188k6.b(i, iA, i2);
        }
    }

    @Override // com.google.android.gms.internal.mlkit_vision_barcode.I6
    public final int c(int i, View view) {
        switch (this.a) {
            case 0:
                return AbstractC3188k6.b(i, ((BottomSheetBehavior) this.b).E(), h());
            default:
                return view.getTop();
        }
    }

    @Override // com.google.android.gms.internal.mlkit_vision_barcode.I6
    public int g(View view) {
        switch (this.a) {
            case 1:
                SideSheetBehavior sideSheetBehavior = (SideSheetBehavior) this.b;
                return sideSheetBehavior.l + sideSheetBehavior.o;
            default:
                return super.g(view);
        }
    }

    @Override // com.google.android.gms.internal.mlkit_vision_barcode.I6
    public int h() {
        switch (this.a) {
            case 0:
                BottomSheetBehavior bottomSheetBehavior = (BottomSheetBehavior) this.b;
                return bottomSheetBehavior.I ? bottomSheetBehavior.d1 : bottomSheetBehavior.G;
            default:
                return super.h();
        }
    }

    @Override // com.google.android.gms.internal.mlkit_vision_barcode.I6
    public final void j(int i) {
        switch (this.a) {
            case 0:
                if (i == 1) {
                    BottomSheetBehavior bottomSheetBehavior = (BottomSheetBehavior) this.b;
                    if (bottomSheetBehavior.K) {
                        bottomSheetBehavior.K(1);
                        break;
                    }
                }
                break;
            default:
                if (i == 1) {
                    SideSheetBehavior sideSheetBehavior = (SideSheetBehavior) this.b;
                    if (sideSheetBehavior.g) {
                        sideSheetBehavior.x(1);
                        break;
                    }
                }
                break;
        }
    }

    @Override // com.google.android.gms.internal.mlkit_vision_barcode.I6
    public final void k(View view, int i, int i2) {
        ViewGroup.MarginLayoutParams marginLayoutParams;
        switch (this.a) {
            case 0:
                ((BottomSheetBehavior) this.b).A(i2);
                return;
            default:
                SideSheetBehavior sideSheetBehavior = (SideSheetBehavior) this.b;
                WeakReference weakReference = sideSheetBehavior.q;
                View view2 = weakReference != null ? (View) weakReference.get() : null;
                if (view2 != null && (marginLayoutParams = (ViewGroup.MarginLayoutParams) view2.getLayoutParams()) != null) {
                    com.google.android.material.sidesheet.a aVar = sideSheetBehavior.a;
                    int left = view.getLeft();
                    int right = view.getRight();
                    switch (aVar.a) {
                        case 0:
                            if (left <= aVar.b.m) {
                                marginLayoutParams.leftMargin = right;
                                break;
                            }
                            break;
                        default:
                            int i3 = aVar.b.m;
                            if (left <= i3) {
                                marginLayoutParams.rightMargin = i3 - left;
                                break;
                            }
                            break;
                    }
                    view2.setLayoutParams(marginLayoutParams);
                }
                LinkedHashSet linkedHashSet = sideSheetBehavior.v;
                if (linkedHashSet.isEmpty()) {
                    return;
                }
                com.google.android.material.sidesheet.a aVar2 = sideSheetBehavior.a;
                switch (aVar2.a) {
                    case 0:
                        aVar2.b();
                        aVar2.a();
                        break;
                    default:
                        int i4 = aVar2.b.m;
                        aVar2.a();
                        break;
                }
                Iterator it2 = linkedHashSet.iterator();
                if (it2.hasNext()) {
                    throw android.support.v4.media.session.a.d(it2);
                }
                return;
        }
    }

    /* JADX WARN: Failed to find 'out' block for switch in B:16:0x0027. Please report as an issue. */
    /* JADX WARN: Failed to find 'out' block for switch in B:26:0x0065. Please report as an issue. */
    /* JADX WARN: Failed to find 'out' block for switch in B:40:0x00ab. Please report as an issue. */
    /* JADX WARN: Failed to find 'out' block for switch in B:5:0x000d. Please report as an issue. */
    /* JADX WARN: Removed duplicated region for block: B:19:0x0042  */
    /* JADX WARN: Removed duplicated region for block: B:20:0x0044  */
    /* JADX WARN: Removed duplicated region for block: B:31:0x0084  */
    /* JADX WARN: Removed duplicated region for block: B:43:0x00bf  */
    /* JADX WARN: Removed duplicated region for block: B:44:0x00c1  */
    /* JADX WARN: Removed duplicated region for block: B:57:0x0107  */
    /* JADX WARN: Removed duplicated region for block: B:65:0x011e  */
    /* JADX WARN: Removed duplicated region for block: B:79:0x015d  */
    /* JADX WARN: Removed duplicated region for block: B:8:0x0015  */
    /* JADX WARN: Removed duplicated region for block: B:93:0x0196  */
    /* JADX WARN: Removed duplicated region for block: B:9:0x0017  */
    @Override // com.google.android.gms.internal.mlkit_vision_barcode.I6
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void l(android.view.View r6, float r7, float r8) {
        /*
            Method dump skipped, instructions count: 536
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.material.bottomsheet.b.l(android.view.View, float, float):void");
    }

    /* JADX WARN: Removed duplicated region for block: B:31:0x0048  */
    @Override // com.google.android.gms.internal.mlkit_vision_barcode.I6
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean m(int r5, android.view.View r6) {
        /*
            r4 = this;
            int r0 = r4.a
            switch(r0) {
                case 0: goto L1c;
                default: goto L5;
            }
        L5:
            androidx.coordinatorlayout.widget.b r5 = r4.b
            com.google.android.material.sidesheet.SideSheetBehavior r5 = (com.google.android.material.sidesheet.SideSheetBehavior) r5
            int r0 = r5.h
            r1 = 0
            r2 = 1
            if (r0 != r2) goto L10
            goto L1b
        L10:
            java.lang.ref.WeakReference r5 = r5.p
            if (r5 == 0) goto L1b
            java.lang.Object r5 = r5.get()
            if (r5 != r6) goto L1b
            r1 = r2
        L1b:
            return r1
        L1c:
            androidx.coordinatorlayout.widget.b r0 = r4.b
            com.google.android.material.bottomsheet.BottomSheetBehavior r0 = (com.google.android.material.bottomsheet.BottomSheetBehavior) r0
            int r1 = r0.L
            r2 = 1
            if (r1 != r2) goto L26
            goto L56
        L26:
            boolean r3 = r0.l1
            if (r3 == 0) goto L2b
            goto L56
        L2b:
            r3 = 3
            if (r1 != r3) goto L48
            int r1 = r0.j1
            if (r1 != r5) goto L48
            java.lang.ref.WeakReference r5 = r0.f1
            if (r5 == 0) goto L3d
            java.lang.Object r5 = r5.get()
            android.view.View r5 = (android.view.View) r5
            goto L3e
        L3d:
            r5 = 0
        L3e:
            if (r5 == 0) goto L48
            r1 = -1
            boolean r5 = r5.canScrollVertically(r1)
            if (r5 == 0) goto L48
            goto L56
        L48:
            java.lang.System.currentTimeMillis()
            java.lang.ref.WeakReference r5 = r0.e1
            if (r5 == 0) goto L56
            java.lang.Object r5 = r5.get()
            if (r5 != r6) goto L56
            goto L57
        L56:
            r2 = 0
        L57:
            return r2
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.material.bottomsheet.b.m(int, android.view.View):boolean");
    }
}
