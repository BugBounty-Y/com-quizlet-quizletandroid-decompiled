package androidx.constraintlayout.widget;

import android.view.View;

/* loaded from: classes.dex */
public final class f implements androidx.constraintlayout.core.widgets.analyzer.c {
    public final ConstraintLayout a;
    public int b;
    public int c;
    public int d;
    public int e;
    public int f;
    public int g;
    public final /* synthetic */ ConstraintLayout h;

    public f(ConstraintLayout constraintLayout, ConstraintLayout constraintLayout2) {
        this.h = constraintLayout;
        this.a = constraintLayout2;
    }

    public static boolean c(int i, int i2, int i3) {
        if (i == i2) {
            return true;
        }
        int mode = View.MeasureSpec.getMode(i);
        int mode2 = View.MeasureSpec.getMode(i2);
        int size = View.MeasureSpec.getSize(i2);
        if (mode2 == 1073741824) {
            return (mode == Integer.MIN_VALUE || mode == 0) && i3 == size;
        }
        return false;
    }

    @Override // androidx.constraintlayout.core.widgets.analyzer.c
    public final void a() {
        ConstraintLayout constraintLayout = this.a;
        int childCount = constraintLayout.getChildCount();
        for (int i = 0; i < childCount; i++) {
            View childAt = constraintLayout.getChildAt(i);
            if (childAt instanceof s) {
                s sVar = (s) childAt;
                if (sVar.b != null) {
                    e eVar = (e) sVar.getLayoutParams();
                    e eVar2 = (e) sVar.b.getLayoutParams();
                    androidx.constraintlayout.core.widgets.e eVar3 = eVar2.q0;
                    eVar3.j0 = 0;
                    androidx.constraintlayout.core.widgets.e eVar4 = eVar.q0;
                    androidx.constraintlayout.core.widgets.d dVar = eVar4.V[0];
                    androidx.constraintlayout.core.widgets.d dVar2 = androidx.constraintlayout.core.widgets.d.a;
                    if (dVar != dVar2) {
                        eVar4.S(eVar3.r());
                    }
                    androidx.constraintlayout.core.widgets.e eVar5 = eVar.q0;
                    if (eVar5.V[1] != dVar2) {
                        eVar5.N(eVar2.q0.l());
                    }
                    eVar2.q0.j0 = 8;
                }
            }
        }
        int size = constraintLayout.b.size();
        if (size > 0) {
            for (int i2 = 0; i2 < size; i2++) {
                ((c) constraintLayout.b.get(i2)).getClass();
            }
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:116:0x01a7  */
    /* JADX WARN: Removed duplicated region for block: B:117:0x01a9  */
    /* JADX WARN: Removed duplicated region for block: B:119:0x01ac  */
    /* JADX WARN: Removed duplicated region for block: B:120:0x01ae  */
    /* JADX WARN: Removed duplicated region for block: B:126:0x01ba  */
    /* JADX WARN: Removed duplicated region for block: B:131:0x01c2  */
    /* JADX WARN: Removed duplicated region for block: B:137:0x01ce  */
    /* JADX WARN: Removed duplicated region for block: B:142:0x01d9  */
    /* JADX WARN: Removed duplicated region for block: B:144:0x01dc A[ORIG_RETURN, RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:145:0x01dd  */
    /* JADX WARN: Removed duplicated region for block: B:55:0x00be  */
    /* JADX WARN: Removed duplicated region for block: B:91:0x012e  */
    @Override // androidx.constraintlayout.core.widgets.analyzer.c
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void b(androidx.constraintlayout.core.widgets.e r18, androidx.constraintlayout.core.widgets.analyzer.b r19) {
        /*
            Method dump skipped, instructions count: 716
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.constraintlayout.widget.f.b(androidx.constraintlayout.core.widgets.e, androidx.constraintlayout.core.widgets.analyzer.b):void");
    }
}
