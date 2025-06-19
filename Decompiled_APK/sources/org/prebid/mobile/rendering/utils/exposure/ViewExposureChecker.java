package org.prebid.mobile.rendering.utils.exposure;

import android.graphics.Rect;
import android.view.View;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import org.prebid.mobile.LogUtil;

/* loaded from: classes3.dex */
public class ViewExposureChecker {
    public WeakReference a;
    public final ArrayList c = new ArrayList();
    public Rect b = new Rect();

    public static Rect b(Rect rect, View view, View view2) {
        if (view == null || view2 == null) {
            LogUtil.e(3, "ViewExposureChecker", "convertRect: Failed. One of the provided param is null. Returning empty rect.");
            return new Rect();
        }
        int[] iArr = new int[2];
        int[] iArr2 = new int[2];
        view.getLocationOnScreen(iArr);
        view2.getLocationOnScreen(iArr2);
        int scrollX = (iArr[0] - iArr2[0]) - view.getScrollX();
        int scrollY = (iArr[1] - iArr2[1]) - view.getScrollY();
        return new Rect(rect.left + scrollX, rect.top + scrollY, rect.right + scrollX, rect.bottom + scrollY);
    }

    public static void c(Rect rect, ArrayList arrayList, ArrayList arrayList2, int i) {
        int size = arrayList.size();
        while (i < size) {
            Rect rect2 = (Rect) arrayList.get(i);
            if (!Rect.intersects(rect2, rect)) {
                arrayList2.add(rect2);
            } else if (!rect.contains(rect2)) {
                Rect rect3 = new Rect(rect);
                if (rect3.intersect(rect2)) {
                    int i2 = rect2.left;
                    int i3 = rect2.top;
                    Rect rect4 = new Rect(i2, i3, (rect3.left - i2) + i2, rect2.height() + i3);
                    int i4 = rect3.left;
                    int i5 = rect2.top;
                    Rect rect5 = new Rect(i4, i5, rect3.right, (rect3.top - i5) + i5);
                    Rect rect6 = new Rect(rect3.left, rect3.bottom, rect3.right, rect2.bottom);
                    int i6 = rect3.right;
                    int i7 = rect2.top;
                    Rect[] rectArr = {rect4, rect5, rect6, new Rect(i6, i7, rect2.right, rect2.height() + i7)};
                    for (int i8 = 0; i8 < 4; i8++) {
                        Rect rect7 = rectArr[i8];
                        if (!rect7.isEmpty()) {
                            arrayList2.add(rect7);
                        }
                    }
                } else {
                    LogUtil.e(3, "ViewExposureChecker", "fragmentize: Error. Rect is not trimmed");
                }
            }
            i++;
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:21:0x0034  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void a(android.view.View r6) {
        /*
            r5 = this;
            boolean r0 = r6.isShown()
            if (r0 == 0) goto L6f
            float r0 = r6.getAlpha()
            r1 = 0
            int r0 = (r0 > r1 ? 1 : (r0 == r1 ? 0 : -1))
            if (r0 != 0) goto L10
            return
        L10:
            boolean r0 = r6 instanceof android.view.ViewGroup
            r1 = 0
            if (r0 != 0) goto L16
            goto L34
        L16:
            android.graphics.drawable.Drawable r2 = r6.getForeground()
            android.graphics.drawable.Drawable r3 = r6.getBackground()
            if (r2 == 0) goto L29
            int r2 = r2.getAlpha()
            if (r2 != 0) goto L27
            goto L29
        L27:
            r2 = r1
            goto L2a
        L29:
            r2 = 1
        L2a:
            if (r3 == 0) goto L32
            int r3 = r3.getAlpha()
            if (r3 != 0) goto L34
        L32:
            if (r2 != 0) goto L5a
        L34:
            android.graphics.Rect r2 = new android.graphics.Rect
            r2.<init>()
            r6.getDrawingRect(r2)
            java.lang.ref.WeakReference r3 = r5.a
            java.lang.Object r3 = r3.get()
            android.view.View r3 = (android.view.View) r3
            android.graphics.Rect r2 = b(r2, r6, r3)
            android.graphics.Rect r3 = new android.graphics.Rect
            android.graphics.Rect r4 = r5.b
            r3.<init>(r4)
            boolean r2 = r3.intersect(r2)
            if (r2 == 0) goto L5a
            java.util.ArrayList r2 = r5.c
            r2.add(r3)
        L5a:
            if (r0 != 0) goto L5d
            goto L6f
        L5d:
            android.view.ViewGroup r6 = (android.view.ViewGroup) r6
        L5f:
            int r0 = r6.getChildCount()
            if (r1 >= r0) goto L6f
            android.view.View r0 = r6.getChildAt(r1)
            r5.a(r0)
            int r1 = r1 + 1
            goto L5f
        L6f:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: org.prebid.mobile.rendering.utils.exposure.ViewExposureChecker.a(android.view.View):void");
    }

    /* JADX WARN: Removed duplicated region for block: B:12:0x0034  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean d(android.view.View r7, android.view.ViewGroup r8) {
        /*
            r6 = this;
            int r0 = r8.getVisibility()
            r1 = 0
            if (r0 != 0) goto L8c
            float r0 = r8.getAlpha()
            r2 = 0
            int r0 = (r0 > r2 ? 1 : (r0 == r2 ? 0 : -1))
            if (r0 != 0) goto L11
            return r1
        L11:
            boolean r0 = r8.getClipChildren()
            if (r0 == 0) goto L34
            android.graphics.Rect r0 = new android.graphics.Rect
            r0.<init>()
            r8.getDrawingRect(r0)
            java.lang.ref.WeakReference r2 = r6.a
            java.lang.Object r2 = r2.get()
            android.view.View r2 = (android.view.View) r2
            android.graphics.Rect r0 = b(r0, r8, r2)
            android.graphics.Rect r2 = r6.b
            boolean r0 = r2.intersect(r0)
            if (r0 != 0) goto L34
            goto L8c
        L34:
            android.view.ViewParent r0 = r8.getParent()
            boolean r0 = r0 instanceof android.view.ViewGroup
            if (r0 == 0) goto L49
            android.view.ViewParent r0 = r8.getParent()
            android.view.ViewGroup r0 = (android.view.ViewGroup) r0
            boolean r0 = r6.d(r8, r0)
            if (r0 != 0) goto L49
            goto L8c
        L49:
            int r7 = r8.indexOfChild(r7)
            r0 = 1
            int r7 = r7 + r0
            int r1 = r8.getChildCount()
        L53:
            if (r7 >= r1) goto L8b
            android.view.View r2 = r8.getChildAt(r7)
            boolean r3 = r2 instanceof android.widget.ImageView
            if (r3 == 0) goto L66
            int r4 = r2.getId()
            r5 = 2131428528(0x7f0b04b0, float:1.8478703E38)
            if (r4 == r5) goto L88
        L66:
            if (r3 == 0) goto L71
            int r3 = r2.getId()
            r4 = 2131428529(0x7f0b04b1, float:1.8478705E38)
            if (r3 == r4) goto L88
        L71:
            int r3 = r2.getId()
            r4 = 2131429153(0x7f0b0721, float:1.847997E38)
            if (r3 != r4) goto L7b
            goto L88
        L7b:
            int r3 = r2.getId()
            r4 = 16908336(0x1020030, float:2.3877364E-38)
            if (r3 != r4) goto L85
            goto L88
        L85:
            r6.a(r2)
        L88:
            int r7 = r7 + 1
            goto L53
        L8b:
            return r0
        L8c:
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: org.prebid.mobile.rendering.utils.exposure.ViewExposureChecker.d(android.view.View, android.view.ViewGroup):boolean");
    }
}
