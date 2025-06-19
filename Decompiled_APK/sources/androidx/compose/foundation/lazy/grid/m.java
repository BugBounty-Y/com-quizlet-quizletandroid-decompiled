package androidx.compose.foundation.lazy.grid;

import android.util.Log;
import android.webkit.WebView;
import androidx.camera.camera2.internal.AbstractC0147y;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.google.android.gms.ads.nonagon.signalgeneration.AbstractC1642h;
import com.google.android.gms.internal.ads.A7;
import com.google.android.gms.internal.ads.AbstractC1972di;
import com.google.android.gms.internal.ads.Bs;
import com.google.android.gms.internal.ads.C2147hi;
import com.google.android.gms.internal.ads.C2210j2;
import com.google.android.gms.internal.ads.C2665tm;
import com.google.android.gms.internal.ads.Gr;
import com.google.android.gms.internal.ads.Hr;
import com.google.android.gms.internal.ads.Ir;
import com.google.android.gms.internal.ads.Mr;
import com.google.android.gms.internal.mlkit_vision_barcode.L5;
import com.google.android.gms.internal.mlkit_vision_barcode.O5;
import com.google.android.gms.internal.mlkit_vision_barcode.V4;
import com.google.android.gms.internal.mlkit_vision_barcode.W4;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayDeque;
import java.util.HashMap;
import java.util.NavigableMap;
import java.util.TreeMap;
import java.util.UUID;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;

/* loaded from: classes.dex */
public final class m {
    public final int a;
    public int b;
    public Object c;
    public Object d;
    public Object e;
    public Object f;

    public /* synthetic */ m(int i, int i2, WebView webView, String str, String str2, String str3) {
        this.c = str;
        this.a = i;
        this.d = str2;
        this.e = webView;
        this.f = str3;
        this.b = i2;
    }

    public void a(long j, float f) {
        int i = (this.b + 1) % 20;
        this.b = i;
        androidx.compose.ui.input.pointer.util.a[] aVarArr = (androidx.compose.ui.input.pointer.util.a[]) this.c;
        androidx.compose.ui.input.pointer.util.a aVar = aVarArr[i];
        if (aVar != null) {
            aVar.a = j;
            aVar.b = f;
        } else {
            androidx.compose.ui.input.pointer.util.a aVar2 = new androidx.compose.ui.input.pointer.util.a();
            aVar2.a = j;
            aVar2.b = f;
            aVarArr[i] = aVar2;
        }
    }

    public float b(float f) {
        float[] fArr;
        float[] fArr2;
        float f2;
        float fSignum;
        float f3 = f;
        float f4 = DefinitionKt.NO_Float_VALUE;
        if (f3 <= DefinitionKt.NO_Float_VALUE) {
            W4.f("maximumVelocity should be a positive value. You specified=" + f3);
            throw null;
        }
        int i = this.b;
        androidx.compose.ui.input.pointer.util.a[] aVarArr = (androidx.compose.ui.input.pointer.util.a[]) this.c;
        androidx.compose.ui.input.pointer.util.a aVar = aVarArr[i];
        if (aVar == null) {
            f2 = 0.0f;
        } else {
            int i2 = 0;
            androidx.compose.ui.input.pointer.util.a aVar2 = aVar;
            while (true) {
                androidx.compose.ui.input.pointer.util.a aVar3 = aVarArr[i];
                fArr = (float[]) this.d;
                fArr2 = (float[]) this.e;
                if (aVar3 == null) {
                    f2 = f4;
                    break;
                }
                long j = aVar.a;
                long j2 = aVar3.a;
                float f5 = j - j2;
                f2 = f4;
                int i3 = i;
                float fAbs = Math.abs(j2 - aVar2.a);
                if (f5 > 100.0f || fAbs > 40.0f) {
                    break;
                }
                fArr[i2] = aVar3.b;
                fArr2[i2] = -f5;
                i = (i3 == 0 ? 20 : i3) - 1;
                i2++;
                if (i2 >= 20) {
                    break;
                }
                aVar2 = aVar3;
                f4 = f2;
            }
            if (i2 >= this.a) {
                int iK = AbstractC0147y.k(1);
                if (iK == 0) {
                    try {
                        float[] fArr3 = (float[]) this.f;
                        V4.j(fArr2, fArr, i2, fArr3);
                        fSignum = fArr3[1];
                    } catch (IllegalArgumentException unused) {
                        fSignum = f2;
                    }
                } else {
                    if (iK != 1) {
                        throw new NoWhenBranchMatchedException();
                    }
                    int i4 = i2 - 1;
                    float f6 = fArr2[i4];
                    int i5 = i4;
                    float fAbs2 = f2;
                    while (i5 > 0) {
                        int i6 = i5 - 1;
                        float f7 = fArr2[i6];
                        if (f6 != f7) {
                            float f8 = (fArr[i5] - fArr[i6]) / (f6 - f7);
                            fAbs2 += Math.abs(f8) * (f8 - (Math.signum(fAbs2) * ((float) Math.sqrt(Math.abs(fAbs2) * 2))));
                            if (i5 == i4) {
                                fAbs2 *= 0.5f;
                            }
                        }
                        i5--;
                        f6 = f7;
                    }
                    fSignum = Math.signum(fAbs2) * ((float) Math.sqrt(Math.abs(fAbs2) * 2));
                }
                f4 = fSignum * 1000;
            } else {
                f4 = f2;
            }
        }
        if (f4 == f2 || Float.isNaN(f4)) {
            return f2;
        }
        if (f4 <= f2) {
            f3 = -f3;
            if (f4 >= f3) {
                return f4;
            }
        } else if (f4 <= f3) {
            f3 = f4;
        }
        return f3;
    }

    public long c(int i, int i2) {
        int i3;
        t tVar = (t) this.c;
        int[] iArr = tVar.a;
        if (i2 == 1) {
            i3 = iArr[i];
        } else {
            int i4 = (i2 + i) - 1;
            int[] iArr2 = tVar.b;
            i3 = (iArr2[i4] + iArr[i4]) - iArr2[i];
        }
        if (i3 < 0) {
            i3 = 0;
        }
        if (i3 >= 0) {
            return L5.m(i3, i3, 0, SubsamplingScaleImageView.TILE_SIZE_AUTO);
        }
        O5.e("width(" + i3 + ") must be >= 0");
        throw null;
    }

    public void d(int i, Class cls) {
        NavigableMap navigableMapJ = j(cls);
        Integer num = (Integer) navigableMapJ.get(Integer.valueOf(i));
        if (num != null) {
            if (num.intValue() == 1) {
                navigableMapJ.remove(Integer.valueOf(i));
                return;
            } else {
                navigableMapJ.put(Integer.valueOf(i), Integer.valueOf(num.intValue() - 1));
                return;
            }
        }
        throw new NullPointerException("Tried to decrement empty size, size: " + i + ", this: " + this);
    }

    public void e(int i) {
        while (this.b > i) {
            Object objN = ((com.quizlet.data.repository.activitycenter.b) this.c).n();
            com.bumptech.glide.util.f.b(objN);
            com.bumptech.glide.load.engine.bitmap_recycle.b bVarG = g(objN.getClass());
            this.b -= bVarG.b() * bVarG.a(objN);
            d(bVarG.a(objN), objN.getClass());
            if (Log.isLoggable(bVarG.c(), 2)) {
                bVarG.a(objN);
            }
        }
    }

    public synchronized Object f(int i, Class cls) {
        com.bumptech.glide.load.engine.bitmap_recycle.d dVar;
        int i2;
        try {
            Integer num = (Integer) j(cls).ceilingKey(Integer.valueOf(i));
            if (num == null || ((i2 = this.b) != 0 && this.a / i2 < 2 && num.intValue() > i * 8)) {
                com.bumptech.glide.load.engine.bitmap_recycle.e eVar = (com.bumptech.glide.load.engine.bitmap_recycle.e) this.d;
                com.bumptech.glide.load.engine.bitmap_recycle.g gVarT = (com.bumptech.glide.load.engine.bitmap_recycle.g) ((ArrayDeque) eVar.b).poll();
                if (gVarT == null) {
                    gVarT = eVar.T();
                }
                dVar = (com.bumptech.glide.load.engine.bitmap_recycle.d) gVarT;
                dVar.b = i;
                dVar.c = cls;
            } else {
                com.bumptech.glide.load.engine.bitmap_recycle.e eVar2 = (com.bumptech.glide.load.engine.bitmap_recycle.e) this.d;
                int iIntValue = num.intValue();
                com.bumptech.glide.load.engine.bitmap_recycle.g gVarT2 = (com.bumptech.glide.load.engine.bitmap_recycle.g) ((ArrayDeque) eVar2.b).poll();
                if (gVarT2 == null) {
                    gVarT2 = eVar2.T();
                }
                dVar = (com.bumptech.glide.load.engine.bitmap_recycle.d) gVarT2;
                dVar.b = iIntValue;
                dVar.c = cls;
            }
        } catch (Throwable th) {
            throw th;
        }
        return i(dVar, cls);
    }

    public com.bumptech.glide.load.engine.bitmap_recycle.b g(Class cls) {
        com.bumptech.glide.load.engine.bitmap_recycle.b bVar;
        HashMap map = (HashMap) this.f;
        com.bumptech.glide.load.engine.bitmap_recycle.b bVar2 = (com.bumptech.glide.load.engine.bitmap_recycle.b) map.get(cls);
        if (bVar2 != null) {
            return bVar2;
        }
        if (cls.equals(int[].class)) {
            bVar = new com.bumptech.glide.load.engine.bitmap_recycle.b(1);
        } else {
            if (!cls.equals(byte[].class)) {
                throw new IllegalArgumentException("No array pool found for: ".concat(cls.getSimpleName()));
            }
            bVar = new com.bumptech.glide.load.engine.bitmap_recycle.b(0);
        }
        map.put(cls, bVar);
        return bVar;
    }

    /* JADX WARN: Type inference failed for: r5v0, types: [java.lang.Object, java.util.List] */
    public s h(int i) {
        com.android.billingclient.api.s sVarB = ((x) this.f).b(i);
        ?? r5 = sVarB.c;
        int size = r5.size();
        int i2 = sVarB.b;
        int i3 = (size == 0 || i2 + size == this.a) ? 0 : this.b;
        r[] rVarArr = new r[size];
        int i4 = 0;
        for (int i5 = 0; i5 < size; i5++) {
            int i6 = (int) ((C0427b) r5.get(i5)).a;
            int i7 = i3;
            r rVarB = ((l) this.e).b(i2 + i5, c(i4, i6), i4, i6, i7);
            i3 = i7;
            i4 += i6;
            Unit unit = Unit.a;
            rVarArr[i5] = rVarB;
        }
        return new s(i, rVarArr, (t) this.d, r5, i3);
    }

    public Object i(com.bumptech.glide.load.engine.bitmap_recycle.d dVar, Class cls) {
        com.bumptech.glide.load.engine.bitmap_recycle.b bVarG = g(cls);
        Object objH = ((com.quizlet.data.repository.activitycenter.b) this.c).h(dVar);
        if (objH != null) {
            this.b -= bVarG.b() * bVarG.a(objH);
            d(bVarG.a(objH), cls);
        }
        if (objH != null) {
            return objH;
        }
        Log.isLoggable(bVarG.c(), 2);
        int i = dVar.b;
        switch (bVarG.a) {
            case 0:
                return new byte[i];
            default:
                return new int[i];
        }
    }

    public NavigableMap j(Class cls) {
        HashMap map = (HashMap) this.e;
        NavigableMap navigableMap = (NavigableMap) map.get(cls);
        if (navigableMap != null) {
            return navigableMap;
        }
        TreeMap treeMap = new TreeMap();
        map.put(cls, treeMap);
        return treeMap;
    }

    public synchronized void k(Object obj) {
        Class<?> cls = obj.getClass();
        com.bumptech.glide.load.engine.bitmap_recycle.b bVarG = g(cls);
        int iA = bVarG.a(obj);
        int iB = bVarG.b() * iA;
        if (iB <= this.a / 2) {
            com.bumptech.glide.load.engine.bitmap_recycle.e eVar = (com.bumptech.glide.load.engine.bitmap_recycle.e) this.d;
            com.bumptech.glide.load.engine.bitmap_recycle.g gVarT = (com.bumptech.glide.load.engine.bitmap_recycle.g) ((ArrayDeque) eVar.b).poll();
            if (gVarT == null) {
                gVarT = eVar.T();
            }
            com.bumptech.glide.load.engine.bitmap_recycle.d dVar = (com.bumptech.glide.load.engine.bitmap_recycle.d) gVarT;
            dVar.b = iA;
            dVar.c = cls;
            ((com.quizlet.data.repository.activitycenter.b) this.c).m(dVar, obj);
            NavigableMap navigableMapJ = j(cls);
            Integer num = (Integer) navigableMapJ.get(Integer.valueOf(dVar.b));
            Integer numValueOf = Integer.valueOf(dVar.b);
            int iIntValue = 1;
            if (num != null) {
                iIntValue = 1 + num.intValue();
            }
            navigableMapJ.put(numValueOf, Integer.valueOf(iIntValue));
            this.b += iB;
            e(this.a);
        }
    }

    public Object l() {
        A7 a7A = A7.a("Google", (String) this.c);
        Mr mrO = C2147hi.o("javascript");
        int i = this.a;
        Ir irM = C2147hi.m(AbstractC1642h.c(i));
        Mr mr = Mr.NONE;
        if (mrO == mr) {
            com.google.android.gms.ads.internal.util.client.i.h("Omid html session error; Unable to parse impression owner: javascript");
            return null;
        }
        if (irM == null) {
            com.google.android.gms.ads.internal.util.client.i.h("Omid html session error; Unable to parse creative type: ".concat(AbstractC1642h.B(i)));
            return null;
        }
        String str = (String) this.d;
        Mr mrO2 = C2147hi.o(str);
        if (irM == Ir.VIDEO && mrO2 == mr) {
            com.google.android.gms.ads.internal.util.client.i.h("Omid html session error; Video events owner unknown for video creative: ".concat(String.valueOf(str)));
            return null;
        }
        C2210j2 c2210j2 = new C2210j2(a7A, (WebView) this.e, (String) this.f, "", Gr.HTML);
        Bs bsA = Bs.a(irM, C2147hi.n(AbstractC1642h.d(this.b)), mrO, mrO2, true);
        if (AbstractC1972di.M.b) {
            return new C2665tm(new Hr(bsA, c2210j2, UUID.randomUUID().toString()), c2210j2);
        }
        throw new IllegalStateException("Method called before OM SDK activation");
    }

    public m(t tVar, int i, int i2, l lVar, x xVar) {
        this.d = tVar;
        this.c = tVar;
        this.a = i;
        this.b = i2;
        this.e = lVar;
        this.f = xVar;
    }

    public m(int i, int i2) {
        switch (i2) {
            case 4:
                this.a = i;
                break;
            default:
                this.c = new com.quizlet.data.repository.activitycenter.b(7);
                this.d = new com.bumptech.glide.load.engine.bitmap_recycle.e(0);
                this.e = new HashMap();
                this.f = new HashMap();
                this.a = i;
                break;
        }
    }

    public m() {
        int i;
        int iK = AbstractC0147y.k(1);
        if (iK == 0) {
            i = 3;
        } else {
            if (iK != 1) {
                throw new NoWhenBranchMatchedException();
            }
            i = 2;
        }
        this.a = i;
        this.c = new androidx.compose.ui.input.pointer.util.a[20];
        this.d = new float[20];
        this.e = new float[20];
        this.f = new float[3];
    }
}
