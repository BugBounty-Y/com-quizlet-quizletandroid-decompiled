package androidx.camera.core.streamsharing;

import android.graphics.Rect;
import android.graphics.RectF;
import android.util.Rational;
import android.util.Size;
import androidx.camera.core.impl.A0;
import androidx.camera.core.impl.InterfaceC0183w;
import androidx.camera.core.impl.InterfaceC0185y;
import com.google.android.gms.internal.measurement.AbstractC3053s1;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;

/* loaded from: classes.dex */
public final class b {
    public static final double h = Math.sqrt(2.3703703703703702d);
    public final Size a;
    public final Rational b;
    public final Rational c;
    public final HashSet d;
    public final com.quizlet.data.repository.set.f e;
    public final InterfaceC0183w f;
    public final HashMap g;

    public b(InterfaceC0185y interfaceC0185y, HashSet hashSet) {
        Size sizeD = androidx.camera.core.impl.utils.f.d(interfaceC0185y.g().b());
        InterfaceC0183w interfaceC0183wN = interfaceC0185y.n();
        com.quizlet.data.repository.set.f fVar = new com.quizlet.data.repository.set.f(interfaceC0183wN, sizeD);
        this.g = new HashMap();
        this.a = sizeD;
        Rational rational = ((double) sizeD.getWidth()) / ((double) sizeD.getHeight()) > h ? androidx.camera.core.impl.utils.b.c : androidx.camera.core.impl.utils.b.a;
        sizeD.toString();
        Objects.toString(rational);
        AbstractC3053s1.f(3, "ResolutionsMerger");
        this.b = rational;
        Rational rational2 = androidx.camera.core.impl.utils.b.a;
        if (rational.equals(rational2)) {
            rational2 = androidx.camera.core.impl.utils.b.c;
        } else if (!rational.equals(androidx.camera.core.impl.utils.b.c)) {
            throw new IllegalArgumentException("Invalid sensor aspect-ratio: " + rational);
        }
        this.c = rational2;
        this.f = interfaceC0183wN;
        this.d = hashSet;
        this.e = fVar;
    }

    public static Rect a(Size size, Size size2) {
        RectF rectF;
        RectF rectF2;
        Rational rationalG = g(size2);
        int width = size.getWidth();
        int height = size.getHeight();
        Rational rationalG2 = g(size);
        if (rationalG.floatValue() == rationalG2.floatValue()) {
            rectF2 = new RectF(DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, width, height);
        } else {
            if (rationalG.floatValue() > rationalG2.floatValue()) {
                float f = width;
                float fFloatValue = f / rationalG.floatValue();
                float f2 = (height - fFloatValue) / 2.0f;
                rectF = new RectF(DefinitionKt.NO_Float_VALUE, f2, f, fFloatValue + f2);
            } else {
                float f3 = height;
                float fFloatValue2 = rationalG.floatValue() * f3;
                float f4 = (width - fFloatValue2) / 2.0f;
                rectF = new RectF(f4, DefinitionKt.NO_Float_VALUE, fFloatValue2 + f4, f3);
            }
            rectF2 = rectF;
        }
        Rect rect = new Rect();
        rectF2.round(rect);
        return rect;
    }

    public static boolean c(Size size, Size size2) {
        return size.getHeight() > size2.getHeight() || size.getWidth() > size2.getWidth();
    }

    public static Rational g(Size size) {
        return new Rational(size.getWidth(), size.getHeight());
    }

    public final List b(A0 a0) {
        Rational rationalG;
        if (!this.d.contains(a0)) {
            throw new IllegalArgumentException("Invalid child config: " + a0);
        }
        HashMap map = this.g;
        if (map.containsKey(a0)) {
            List list = (List) map.get(a0);
            Objects.requireNonNull(list);
            return list;
        }
        ArrayList<Size> arrayListL = this.e.l(a0);
        HashMap map2 = new HashMap();
        ArrayList arrayList = new ArrayList();
        for (Size size : arrayListL) {
            Iterator it2 = map2.keySet().iterator();
            while (true) {
                if (!it2.hasNext()) {
                    rationalG = null;
                    break;
                }
                rationalG = (Rational) it2.next();
                if (androidx.camera.core.impl.utils.b.a(rationalG, size)) {
                    break;
                }
            }
            if (rationalG != null) {
                Size size2 = (Size) map2.get(rationalG);
                Objects.requireNonNull(size2);
                if (size.getHeight() > size2.getHeight() || size.getWidth() > size2.getWidth() || (size.getWidth() == size2.getWidth() && size.getHeight() == size2.getHeight())) {
                }
            } else {
                rationalG = g(size);
            }
            arrayList.add(size);
            map2.put(rationalG, size);
        }
        map.put(a0, arrayList);
        return arrayList;
    }

    public final boolean d(Rational rational, Size size) {
        Rational rational2 = this.b;
        if (rational2.equals(rational) || androidx.camera.core.impl.utils.b.a(rational, size)) {
            return false;
        }
        float fFloatValue = rational2.floatValue();
        float fFloatValue2 = rational.floatValue();
        Rational rationalG = androidx.camera.core.impl.utils.b.a;
        if (!androidx.camera.core.impl.utils.b.a(rationalG, size)) {
            rationalG = androidx.camera.core.impl.utils.b.c;
            if (!androidx.camera.core.impl.utils.b.a(rationalG, size)) {
                rationalG = g(size);
            }
        }
        float fFloatValue3 = rationalG.floatValue();
        if (fFloatValue == fFloatValue2 || fFloatValue2 == fFloatValue3) {
            return false;
        }
        return fFloatValue > fFloatValue2 ? fFloatValue2 < fFloatValue3 : fFloatValue2 > fFloatValue3;
    }

    public final ArrayList e(List list, boolean z) {
        List arrayList;
        HashMap map = new HashMap();
        Rational rational = androidx.camera.core.impl.utils.b.a;
        map.put(rational, new ArrayList());
        Rational rational2 = androidx.camera.core.impl.utils.b.c;
        map.put(rational2, new ArrayList());
        ArrayList arrayList2 = new ArrayList();
        arrayList2.add(rational);
        arrayList2.add(rational2);
        Iterator it2 = list.iterator();
        while (it2.hasNext()) {
            Size size = (Size) it2.next();
            if (size.getHeight() > 0) {
                Iterator it3 = arrayList2.iterator();
                while (true) {
                    if (!it3.hasNext()) {
                        arrayList = null;
                        break;
                    }
                    Rational rational3 = (Rational) it3.next();
                    if (androidx.camera.core.impl.utils.b.a(rational3, size)) {
                        arrayList = (List) map.get(rational3);
                        break;
                    }
                }
                if (arrayList == null) {
                    arrayList = new ArrayList();
                    Rational rationalG = g(size);
                    arrayList2.add(rationalG);
                    map.put(rationalG, arrayList);
                }
                arrayList.add(size);
            }
        }
        ArrayList arrayList3 = new ArrayList(map.keySet());
        Collections.sort(arrayList3, new a(g(this.a), 0));
        ArrayList arrayList4 = new ArrayList();
        Iterator it4 = arrayList3.iterator();
        while (it4.hasNext()) {
            Rational rational4 = (Rational) it4.next();
            if (!rational4.equals(androidx.camera.core.impl.utils.b.c) && !rational4.equals(androidx.camera.core.impl.utils.b.a)) {
                List list2 = (List) map.get(rational4);
                Objects.requireNonNull(list2);
                arrayList4.addAll(f(rational4, list2, z));
            }
        }
        return arrayList4;
    }

    public final ArrayList f(Rational rational, List list, boolean z) {
        ArrayList arrayList;
        ArrayList<Size> arrayList2 = new ArrayList();
        Iterator it2 = list.iterator();
        while (it2.hasNext()) {
            Size size = (Size) it2.next();
            if (androidx.camera.core.impl.utils.b.a(rational, size)) {
                arrayList2.add(size);
            }
        }
        Collections.sort(arrayList2, new androidx.camera.core.impl.utils.c(true));
        HashSet hashSet = new HashSet(arrayList2);
        Iterator it3 = this.d.iterator();
        while (it3.hasNext()) {
            List<Size> listB = b((A0) it3.next());
            if (!z) {
                ArrayList arrayList3 = new ArrayList();
                for (Size size2 : listB) {
                    if (!d(rational, size2)) {
                        arrayList3.add(size2);
                    }
                }
                listB = arrayList3;
            }
            if (listB.isEmpty()) {
                return new ArrayList();
            }
            if (listB.isEmpty() || arrayList2.isEmpty()) {
                arrayList2 = new ArrayList();
            } else {
                ArrayList arrayList4 = new ArrayList();
                for (Size size3 : arrayList2) {
                    Iterator it4 = listB.iterator();
                    while (true) {
                        if (!it4.hasNext()) {
                            break;
                        }
                        if (!c((Size) it4.next(), size3)) {
                            arrayList4.add(size3);
                            break;
                        }
                    }
                }
                arrayList2 = arrayList4;
            }
            if (listB.isEmpty() || arrayList2.isEmpty()) {
                arrayList = new ArrayList();
            } else {
                ArrayList<Size> arrayList5 = arrayList2.isEmpty() ? arrayList2 : new ArrayList(new LinkedHashSet(arrayList2));
                arrayList = new ArrayList();
                for (Size size4 : arrayList5) {
                    Iterator it5 = listB.iterator();
                    while (true) {
                        if (!it5.hasNext()) {
                            arrayList.add(size4);
                            break;
                        }
                        if (c((Size) it5.next(), size4)) {
                            break;
                        }
                    }
                }
                if (!arrayList.isEmpty()) {
                    arrayList.remove(arrayList.size() - 1);
                }
            }
            hashSet.retainAll(arrayList);
        }
        ArrayList arrayList6 = new ArrayList();
        for (Size size5 : arrayList2) {
            if (!hashSet.contains(size5)) {
                arrayList6.add(size5);
            }
        }
        return arrayList6;
    }
}
