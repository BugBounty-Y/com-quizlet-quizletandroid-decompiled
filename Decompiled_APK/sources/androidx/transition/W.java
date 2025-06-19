package androidx.transition;

import android.animation.ObjectAnimator;
import android.view.View;
import android.view.ViewGroup;
import java.util.HashMap;

/* loaded from: classes.dex */
public abstract class W extends y {
    public static final String[] G = {"android:visibility:visibility", "android:visibility:parent"};
    public int F = 3;

    public static void R(I i) {
        int visibility = i.b.getVisibility();
        HashMap map = i.a;
        map.put("android:visibility:visibility", Integer.valueOf(visibility));
        View view = i.b;
        map.put("android:visibility:parent", view.getParent());
        int[] iArr = new int[2];
        view.getLocationOnScreen(iArr);
        map.put("android:visibility:screenLocation", iArr);
    }

    /* JADX WARN: Removed duplicated region for block: B:12:0x0052  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x002f  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static androidx.transition.V S(androidx.transition.I r8, androidx.transition.I r9) {
        /*
            androidx.transition.V r0 = new androidx.transition.V
            r0.<init>()
            r1 = 0
            r0.c = r1
            r0.d = r1
            r2 = 0
            r3 = -1
            java.lang.String r4 = "android:visibility:parent"
            java.lang.String r5 = "android:visibility:visibility"
            if (r8 == 0) goto L2f
            java.util.HashMap r6 = r8.a
            boolean r7 = r6.containsKey(r5)
            if (r7 == 0) goto L2f
            java.lang.Object r7 = r6.get(r5)
            java.lang.Integer r7 = (java.lang.Integer) r7
            int r7 = r7.intValue()
            r0.a = r7
            java.lang.Object r6 = r6.get(r4)
            android.view.ViewGroup r6 = (android.view.ViewGroup) r6
            r0.e = r6
            goto L33
        L2f:
            r0.a = r3
            r0.e = r2
        L33:
            if (r9 == 0) goto L52
            java.util.HashMap r6 = r9.a
            boolean r7 = r6.containsKey(r5)
            if (r7 == 0) goto L52
            java.lang.Object r2 = r6.get(r5)
            java.lang.Integer r2 = (java.lang.Integer) r2
            int r2 = r2.intValue()
            r0.b = r2
            java.lang.Object r2 = r6.get(r4)
            android.view.ViewGroup r2 = (android.view.ViewGroup) r2
            r0.f = r2
            goto L56
        L52:
            r0.b = r3
            r0.f = r2
        L56:
            r2 = 1
            if (r8 == 0) goto L92
            if (r9 == 0) goto L92
            int r8 = r0.a
            int r9 = r0.b
            if (r8 != r9) goto L6c
            java.lang.Object r3 = r0.e
            android.view.ViewGroup r3 = (android.view.ViewGroup) r3
            java.lang.Object r4 = r0.f
            android.view.ViewGroup r4 = (android.view.ViewGroup) r4
            if (r3 != r4) goto L6c
            goto La7
        L6c:
            if (r8 == r9) goto L7c
            if (r8 != 0) goto L75
            r0.d = r1
            r0.c = r2
            return r0
        L75:
            if (r9 != 0) goto La7
            r0.d = r2
            r0.c = r2
            return r0
        L7c:
            java.lang.Object r8 = r0.f
            android.view.ViewGroup r8 = (android.view.ViewGroup) r8
            if (r8 != 0) goto L87
            r0.d = r1
            r0.c = r2
            return r0
        L87:
            java.lang.Object r8 = r0.e
            android.view.ViewGroup r8 = (android.view.ViewGroup) r8
            if (r8 != 0) goto La7
            r0.d = r2
            r0.c = r2
            return r0
        L92:
            if (r8 != 0) goto L9d
            int r8 = r0.b
            if (r8 != 0) goto L9d
            r0.d = r2
            r0.c = r2
            return r0
        L9d:
            if (r9 != 0) goto La7
            int r8 = r0.a
            if (r8 != 0) goto La7
            r0.d = r1
            r0.c = r2
        La7:
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.transition.W.S(androidx.transition.I, androidx.transition.I):androidx.transition.V");
    }

    public abstract ObjectAnimator T(ViewGroup viewGroup, View view, I i, I i2);

    public abstract ObjectAnimator U(ViewGroup viewGroup, View view, I i, I i2);

    @Override // androidx.transition.y
    public void e(I i) {
        R(i);
    }

    /* JADX WARN: Code restructure failed: missing block: B:19:0x0047, code lost:
    
        if (S(p(r5, false), t(r5, false)).c != false) goto L9;
     */
    /* JADX WARN: Removed duplicated region for block: B:48:0x0097  */
    /* JADX WARN: Removed duplicated region for block: B:77:0x01de  */
    /* JADX WARN: Removed duplicated region for block: B:85:0x0216  */
    @Override // androidx.transition.y
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final android.animation.Animator m(android.view.ViewGroup r24, androidx.transition.I r25, androidx.transition.I r26) throws java.lang.IllegalAccessException, java.lang.NoSuchFieldException, java.lang.SecurityException, java.lang.IllegalArgumentException {
        /*
            Method dump skipped, instructions count: 688
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.transition.W.m(android.view.ViewGroup, androidx.transition.I, androidx.transition.I):android.animation.Animator");
    }

    @Override // androidx.transition.y
    public final String[] s() {
        return G;
    }

    @Override // androidx.transition.y
    public final boolean w(I i, I i2) {
        if (i == null && i2 == null) {
            return false;
        }
        if (i != null && i2 != null && i2.a.containsKey("android:visibility:visibility") != i.a.containsKey("android:visibility:visibility")) {
            return false;
        }
        V vS = S(i, i2);
        if (vS.c) {
            return vS.a == 0 || vS.b == 0;
        }
        return false;
    }
}
