package androidx.recyclerview.widget;

import android.view.View;
import java.util.ArrayList;
import java.util.Collections;
import java.util.concurrent.ExecutorService;

/* renamed from: androidx.recyclerview.widget.c, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public abstract class AbstractC1358c {
    public static ExecutorService b;
    public static final Object a = new Object();
    public static final r c = new r(0);

    public static C1392u c(AbstractC1389s abstractC1389s) {
        int i;
        C1395x c1395x;
        int i2;
        C1394w c1394w;
        int i3;
        int i4;
        C1395x c1395x2;
        C1395x c1395x3;
        int i5;
        int i6;
        int i7;
        int i8;
        int i9;
        int i10;
        int i11;
        int i12;
        int i13;
        int oldListSize = abstractC1389s.getOldListSize();
        int newListSize = abstractC1389s.getNewListSize();
        ArrayList arrayList = new ArrayList();
        ArrayList arrayList2 = new ArrayList();
        C1394w c1394w2 = new C1394w();
        int i14 = 0;
        c1394w2.a = 0;
        c1394w2.b = oldListSize;
        c1394w2.c = 0;
        c1394w2.d = newListSize;
        arrayList2.add(c1394w2);
        int i15 = oldListSize + newListSize;
        int i16 = 1;
        int i17 = (((i15 + 1) / 2) * 2) + 1;
        int[] iArr = new int[i17];
        int i18 = i17 / 2;
        int[] iArr2 = new int[i17];
        ArrayList arrayList3 = new ArrayList();
        while (!arrayList2.isEmpty()) {
            C1394w c1394w3 = (C1394w) arrayList2.remove(arrayList2.size() - i16);
            if (c1394w3.b() < i16 || c1394w3.a() < i16) {
                i = i18;
                c1395x = null;
            } else {
                int iA = ((c1394w3.a() + c1394w3.b()) + i16) / 2;
                int i19 = i16 + i18;
                iArr[i19] = c1394w3.a;
                iArr2[i19] = c1394w3.b;
                int i20 = i14;
                while (i20 < iA) {
                    int i21 = Math.abs(c1394w3.b() - c1394w3.a()) % 2 == i16 ? i16 : i14;
                    int iB = c1394w3.b() - c1394w3.a();
                    int i22 = -i20;
                    int i23 = i22;
                    while (true) {
                        if (i23 > i20) {
                            i3 = i14;
                            i = i18;
                            i4 = iA;
                            c1395x2 = null;
                            break;
                        }
                        if (i23 == i22 || (i23 != i20 && iArr[i23 + 1 + i18] > iArr[(i23 - 1) + i18])) {
                            i9 = iArr[i23 + 1 + i18];
                            i10 = i9;
                        } else {
                            i9 = iArr[(i23 - 1) + i18];
                            i10 = i9 + 1;
                        }
                        i = i18;
                        int i24 = ((i10 - c1394w3.a) + c1394w3.c) - i23;
                        if (i20 == 0 || i10 != i9) {
                            i11 = i10;
                            i12 = i24;
                        } else {
                            i11 = i10;
                            i12 = i24 - 1;
                        }
                        int i25 = i23;
                        int i26 = i24;
                        int i27 = i11;
                        i4 = iA;
                        while (i27 < c1394w3.b && i26 < c1394w3.d && abstractC1389s.areItemsTheSame(i27, i26)) {
                            i27++;
                            i26++;
                        }
                        iArr[i25 + i] = i27;
                        if (i21 != 0) {
                            int i28 = iB - i25;
                            i13 = i21;
                            if (i28 >= i22 + 1 && i28 <= i20 - 1 && iArr2[i28 + i] <= i27) {
                                c1395x2 = new C1395x();
                                c1395x2.a = i9;
                                c1395x2.b = i12;
                                c1395x2.c = i27;
                                c1395x2.e = i26;
                                i3 = 0;
                                c1395x2.d = false;
                                break;
                            }
                        } else {
                            i13 = i21;
                        }
                        i23 = i25 + 2;
                        i14 = 0;
                        i18 = i;
                        iA = i4;
                        i21 = i13;
                    }
                    if (c1395x2 != null) {
                        c1395x = c1395x2;
                        break;
                    }
                    int i29 = (c1394w3.b() - c1394w3.a()) % 2 == 0 ? 1 : i3;
                    int iB2 = c1394w3.b() - c1394w3.a();
                    int i30 = i22;
                    while (true) {
                        if (i30 > i20) {
                            c1395x3 = null;
                            break;
                        }
                        if (i30 == i22 || (i30 != i20 && iArr2[i30 + 1 + i] < iArr2[(i30 - 1) + i])) {
                            i5 = iArr2[i30 + 1 + i];
                            i6 = i5;
                        } else {
                            i5 = iArr2[(i30 - 1) + i];
                            i6 = i5 - 1;
                        }
                        int i31 = c1394w3.d - ((c1394w3.b - i6) - i30);
                        int i32 = (i20 == 0 || i6 != i5) ? i31 : i31 + 1;
                        int i33 = i29;
                        while (i6 > c1394w3.a && i31 > c1394w3.c) {
                            i7 = iB2;
                            if (!abstractC1389s.areItemsTheSame(i6 - 1, i31 - 1)) {
                                break;
                            }
                            i6--;
                            i31--;
                            iB2 = i7;
                        }
                        i7 = iB2;
                        iArr2[i30 + i] = i6;
                        if (i33 != 0 && (i8 = i7 - i30) >= i22 && i8 <= i20 && iArr[i8 + i] >= i6) {
                            c1395x3 = new C1395x();
                            c1395x3.a = i6;
                            c1395x3.b = i31;
                            c1395x3.c = i5;
                            c1395x3.e = i32;
                            c1395x3.d = true;
                            break;
                        }
                        i30 += 2;
                        i29 = i33;
                        iB2 = i7;
                    }
                    if (c1395x3 != null) {
                        c1395x = c1395x3;
                        break;
                    }
                    i20++;
                    i18 = i;
                    iA = i4;
                    i16 = 1;
                    i14 = 0;
                }
                i = i18;
                c1395x = null;
            }
            if (c1395x != null) {
                if (c1395x.a() > 0) {
                    int i34 = c1395x.e;
                    int i35 = c1395x.b;
                    int i36 = i34 - i35;
                    int i37 = c1395x.c;
                    int i38 = c1395x.a;
                    int i39 = i37 - i38;
                    arrayList.add(i36 != i39 ? c1395x.d ? new C1391t(i38, i35, c1395x.a()) : i36 > i39 ? new C1391t(i38, i35 + 1, c1395x.a()) : new C1391t(i38 + 1, i35, c1395x.a()) : new C1391t(i38, i35, i39));
                }
                if (arrayList3.isEmpty()) {
                    c1394w = new C1394w();
                    i2 = 1;
                } else {
                    i2 = 1;
                    c1394w = (C1394w) arrayList3.remove(arrayList3.size() - 1);
                }
                c1394w.a = c1394w3.a;
                c1394w.c = c1394w3.c;
                c1394w.b = c1395x.a;
                c1394w.d = c1395x.b;
                arrayList2.add(c1394w);
                c1394w3.b = c1394w3.b;
                c1394w3.d = c1394w3.d;
                c1394w3.a = c1395x.c;
                c1394w3.c = c1395x.e;
                arrayList2.add(c1394w3);
            } else {
                i2 = 1;
                arrayList3.add(c1394w3);
            }
            i18 = i;
            i16 = i2;
            i14 = 0;
        }
        Collections.sort(arrayList, c);
        return new C1392u(abstractC1389s, arrayList, iArr, iArr2);
    }

    public static int d(B0 b0, androidx.emoji2.text.g gVar, View view, View view2, AbstractC1381n0 abstractC1381n0, boolean z) {
        if (abstractC1381n0.v() == 0 || b0.b() == 0 || view == null || view2 == null) {
            return 0;
        }
        if (!z) {
            return Math.abs(AbstractC1381n0.K(view) - AbstractC1381n0.K(view2)) + 1;
        }
        return Math.min(gVar.l(), gVar.b(view2) - gVar.e(view));
    }

    public static int e(B0 b0, androidx.emoji2.text.g gVar, View view, View view2, AbstractC1381n0 abstractC1381n0, boolean z, boolean z2) {
        if (abstractC1381n0.v() == 0 || b0.b() == 0 || view == null || view2 == null) {
            return 0;
        }
        int iMax = z2 ? Math.max(0, (b0.b() - Math.max(AbstractC1381n0.K(view), AbstractC1381n0.K(view2))) - 1) : Math.max(0, Math.min(AbstractC1381n0.K(view), AbstractC1381n0.K(view2)));
        if (z) {
            return Math.round((iMax * (Math.abs(gVar.b(view2) - gVar.e(view)) / (Math.abs(AbstractC1381n0.K(view) - AbstractC1381n0.K(view2)) + 1))) + (gVar.k() - gVar.e(view)));
        }
        return iMax;
    }

    public static int f(B0 b0, androidx.emoji2.text.g gVar, View view, View view2, AbstractC1381n0 abstractC1381n0, boolean z) {
        if (abstractC1381n0.v() == 0 || b0.b() == 0 || view == null || view2 == null) {
            return 0;
        }
        if (!z) {
            return b0.b();
        }
        return (int) (((gVar.b(view2) - gVar.e(view)) / (Math.abs(AbstractC1381n0.K(view) - AbstractC1381n0.K(view2)) + 1)) * b0.b());
    }

    public abstract boolean a(Object obj, Object obj2);

    public abstract boolean b(Object obj, Object obj2);
}
