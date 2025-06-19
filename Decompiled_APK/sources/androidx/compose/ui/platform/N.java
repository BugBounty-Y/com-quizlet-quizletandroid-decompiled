package androidx.compose.ui.platform;

import android.graphics.Rect;
import android.graphics.Region;
import android.os.Binder;
import android.os.Build;
import android.os.Parcelable;
import android.util.Size;
import android.util.SizeF;
import android.util.SparseArray;
import android.view.View;
import androidx.collection.AbstractC0214l;
import androidx.collection.C0223v;
import androidx.compose.animation.core.C0242g;
import androidx.compose.ui.graphics.C0850j;
import androidx.compose.ui.layout.AbstractC0897s;
import androidx.compose.ui.node.AbstractC0910f;
import androidx.compose.ui.node.InterfaceC0917m;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3142f5;
import com.skydoves.balloon.internals.DefinitionKt;
import java.io.Serializable;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import kotlin.InterfaceC4938g;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public abstract class N {
    public static final Class[] b = {Serializable.class, Parcelable.class, String.class, SparseArray.class, Binder.class, Size.class, SizeF.class};
    public static final androidx.compose.ui.geometry.c c = new androidx.compose.ui.geometry.c(DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 10.0f, 10.0f);

    public static final boolean A(androidx.compose.ui.graphics.O o, float f, float f2) {
        androidx.compose.ui.geometry.c cVar = new androidx.compose.ui.geometry.c(f - 0.005f, f2 - 0.005f, f + 0.005f, f2 + 0.005f);
        C0850j c0850jH = androidx.compose.ui.graphics.F.h();
        androidx.compose.ui.graphics.O.a(c0850jH, cVar);
        C0850j c0850jH2 = androidx.compose.ui.graphics.F.h();
        c0850jH2.d(o, c0850jH, 1);
        boolean zIsEmpty = c0850jH2.a.isEmpty();
        c0850jH2.e();
        c0850jH.e();
        return !zIsEmpty;
    }

    public static final boolean B(androidx.compose.ui.semantics.o oVar) {
        androidx.compose.ui.node.a0 a0VarC = oVar.c();
        if (!(a0VarC != null ? a0VarC.d1() : false)) {
            if (!oVar.d.a.containsKey(androidx.compose.ui.semantics.r.m)) {
                return true;
            }
        }
        return false;
    }

    public static final boolean C(float f, float f2, long j, float f3, float f4) {
        float f5 = f - f3;
        float f6 = f2 - f4;
        float fB = androidx.compose.ui.geometry.a.b(j);
        float fC = androidx.compose.ui.geometry.a.c(j);
        return ((f6 * f6) / (fC * fC)) + ((f5 * f5) / (fB * fB)) <= 1.0f;
    }

    public static final void D(float[] fArr, float[] fArr2) {
        float fT = t(fArr2, 0, fArr, 0);
        float fT2 = t(fArr2, 0, fArr, 1);
        float fT3 = t(fArr2, 0, fArr, 2);
        float fT4 = t(fArr2, 0, fArr, 3);
        float fT5 = t(fArr2, 1, fArr, 0);
        float fT6 = t(fArr2, 1, fArr, 1);
        float fT7 = t(fArr2, 1, fArr, 2);
        float fT8 = t(fArr2, 1, fArr, 3);
        float fT9 = t(fArr2, 2, fArr, 0);
        float fT10 = t(fArr2, 2, fArr, 1);
        float fT11 = t(fArr2, 2, fArr, 2);
        float fT12 = t(fArr2, 2, fArr, 3);
        float fT13 = t(fArr2, 3, fArr, 0);
        float fT14 = t(fArr2, 3, fArr, 1);
        float fT15 = t(fArr2, 3, fArr, 2);
        float fT16 = t(fArr2, 3, fArr, 3);
        fArr[0] = fT;
        fArr[1] = fT2;
        fArr[2] = fT3;
        fArr[3] = fT4;
        fArr[4] = fT5;
        fArr[5] = fT6;
        fArr[6] = fT7;
        fArr[7] = fT8;
        fArr[8] = fT9;
        fArr[9] = fT10;
        fArr[10] = fT11;
        fArr[11] = fT12;
        fArr[12] = fT13;
        fArr[13] = fT14;
        fArr[14] = fT15;
        fArr[15] = fT16;
    }

    public static final androidx.compose.ui.viewinterop.i E(C0941f0 c0941f0, int i) {
        Object next;
        Iterator<T> it2 = c0941f0.getLayoutNodeToHolder().entrySet().iterator();
        while (true) {
            if (!it2.hasNext()) {
                next = null;
                break;
            }
            next = it2.next();
            if (((androidx.compose.ui.node.E) ((Map.Entry) next).getKey()).b == i) {
                break;
            }
        }
        Map.Entry entry = (Map.Entry) next;
        if (entry != null) {
            return (androidx.compose.ui.viewinterop.i) entry.getValue();
        }
        return null;
    }

    public static final String F(Object obj) {
        String name = obj.getClass().isAnonymousClass() ? obj.getClass().getName() : obj.getClass().getSimpleName();
        StringBuilder sb = new StringBuilder();
        sb.append(name);
        sb.append('@');
        String str = String.format("%07x", Arrays.copyOf(new Object[]{Integer.valueOf(System.identityHashCode(obj))}, 1));
        Intrinsics.checkNotNullExpressionValue(str, "format(format, *args)");
        sb.append(str);
        return sb.toString();
    }

    public static final androidx.compose.ui.q G(androidx.compose.ui.q qVar, String str) {
        return qVar.g(new TestTagElement(str));
    }

    public static final String H(int i) {
        if (i == 0) {
            return "android.widget.Button";
        }
        if (i == 1) {
            return "android.widget.CheckBox";
        }
        if (i == 3) {
            return "android.widget.RadioButton";
        }
        if (i == 5) {
            return "android.widget.ImageView";
        }
        if (i == 6) {
            return "android.widget.Spinner";
        }
        return null;
    }

    public static void I(View view) {
        try {
            if (!a1.s) {
                a1.s = true;
                if (Build.VERSION.SDK_INT < 28) {
                    a1.q = View.class.getDeclaredMethod("updateDisplayListIfDirty", null);
                    a1.r = View.class.getDeclaredField("mRecreateDisplayList");
                } else {
                    a1.q = (Method) Class.class.getDeclaredMethod("getDeclaredMethod", String.class, new Class[0].getClass()).invoke(View.class, "updateDisplayListIfDirty", new Class[0]);
                    a1.r = (Field) Class.class.getDeclaredMethod("getDeclaredField", String.class).invoke(View.class, "mRecreateDisplayList");
                }
                Method method = a1.q;
                if (method != null) {
                    method.setAccessible(true);
                }
                Field field = a1.r;
                if (field != null) {
                    field.setAccessible(true);
                }
            }
            Field field2 = a1.r;
            if (field2 != null) {
                field2.setBoolean(view, true);
            }
            Method method2 = a1.q;
            if (method2 != null) {
                method2.invoke(view, null);
            }
        } catch (Throwable unused) {
            a1.t = true;
        }
    }

    public static final boolean l(androidx.compose.ui.semantics.o oVar) {
        androidx.compose.ui.semantics.k kVarI = oVar.i();
        return !kVarI.a.containsKey(androidx.compose.ui.semantics.r.i);
    }

    public static final int n(long j) {
        int i = Math.abs(androidx.compose.ui.geometry.b.d(j)) >= 0.5f ? 1 : 0;
        return Math.abs(androidx.compose.ui.geometry.b.e(j)) >= 0.5f ? i | 2 : i;
    }

    public static final C0242g o(AbstractC0930a abstractC0930a, androidx.lifecycle.C c2) {
        if (((androidx.lifecycle.L) c2).d.compareTo(androidx.lifecycle.B.a) > 0) {
            X0 x0 = new X0(abstractC0930a, 0);
            c2.a(x0);
            return new C0242g(27, c2, x0);
        }
        throw new IllegalStateException(("Cannot configure " + abstractC0930a + " to disposeComposition at Lifecycle ON_DESTROY: " + c2 + "is already destroyed").toString());
    }

    public static final boolean p(androidx.compose.ui.semantics.o oVar) {
        return oVar.c.s == androidx.compose.ui.unit.k.b;
    }

    /* JADX WARN: Removed duplicated region for block: B:14:0x003c A[PHI: r6
  0x003c: PHI (r6v2 float) = (r6v1 float), (r6v3 float) binds: [B:16:0x0048, B:13:0x003a] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Removed duplicated region for block: B:6:0x0018 A[PHI: r2
  0x0018: PHI (r2v4 float) = (r2v1 float), (r2v5 float) binds: [B:8:0x0024, B:5:0x0016] A[DONT_GENERATE, DONT_INLINE]] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final long q(int[] r5, long r6) {
        /*
            float r0 = androidx.compose.ui.geometry.b.d(r6)
            r1 = 0
            int r0 = (r0 > r1 ? 1 : (r0 == r1 ? 0 : -1))
            r2 = 0
            r3 = -1082130432(0xffffffffbf800000, float:-1.0)
            if (r0 < 0) goto L1a
            r0 = r5[r2]
            float r0 = (float) r0
            float r0 = r0 * r3
            float r2 = androidx.compose.ui.geometry.b.d(r6)
            int r4 = (r0 > r2 ? 1 : (r0 == r2 ? 0 : -1))
            if (r4 <= 0) goto L27
        L18:
            r0 = r2
            goto L27
        L1a:
            r0 = r5[r2]
            float r0 = (float) r0
            float r0 = r0 * r3
            float r2 = androidx.compose.ui.geometry.b.d(r6)
            int r4 = (r0 > r2 ? 1 : (r0 == r2 ? 0 : -1))
            if (r4 >= 0) goto L27
            goto L18
        L27:
            float r2 = androidx.compose.ui.geometry.b.e(r6)
            int r1 = (r2 > r1 ? 1 : (r2 == r1 ? 0 : -1))
            r2 = 1
            if (r1 < 0) goto L3e
            r5 = r5[r2]
            float r5 = (float) r5
            float r5 = r5 * r3
            float r6 = androidx.compose.ui.geometry.b.e(r6)
            int r7 = (r5 > r6 ? 1 : (r5 == r6 ? 0 : -1))
            if (r7 <= 0) goto L4b
        L3c:
            r5 = r6
            goto L4b
        L3e:
            r5 = r5[r2]
            float r5 = (float) r5
            float r5 = r5 * r3
            float r6 = androidx.compose.ui.geometry.b.e(r6)
            int r7 = (r5 > r6 ? 1 : (r5 == r6 ? 0 : -1))
            if (r7 >= 0) goto L4b
            goto L3c
        L4b:
            long r5 = com.google.android.gms.internal.mlkit_vision_barcode.Q4.c(r0, r5)
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.platform.N.q(int[], long):long");
    }

    public static final boolean r(Object obj) {
        if (obj instanceof androidx.compose.runtime.snapshots.o) {
            androidx.compose.runtime.snapshots.o oVar = (androidx.compose.runtime.snapshots.o) obj;
            if (oVar.d() == androidx.compose.runtime.V.c || oVar.d() == androidx.compose.runtime.V.f || oVar.d() == androidx.compose.runtime.V.d) {
                Object value = oVar.getValue();
                if (value == null) {
                    return true;
                }
                return r(value);
            }
        } else {
            if ((obj instanceof InterfaceC4938g) && (obj instanceof Serializable)) {
                return false;
            }
            Class[] clsArr = b;
            for (int i = 0; i < 7; i++) {
                if (clsArr[i].isInstance(obj)) {
                    return true;
                }
            }
        }
        return false;
    }

    public static final int s(float f) {
        return ((int) (f >= DefinitionKt.NO_Float_VALUE ? Math.ceil(f) : Math.floor(f))) * (-1);
    }

    public static final float t(float[] fArr, int i, float[] fArr2, int i2) {
        int i3 = i * 4;
        return (fArr[i3 + 3] * fArr2[12 + i2]) + (fArr[i3 + 2] * fArr2[8 + i2]) + (fArr[i3 + 1] * fArr2[4 + i2]) + (fArr[i3] * fArr2[i2]);
    }

    public static final C0223v u(androidx.compose.ui.semantics.p pVar) {
        androidx.compose.ui.semantics.o oVarA = pVar.a();
        C0223v c0223v = AbstractC0214l.a;
        C0223v c0223v2 = new C0223v();
        androidx.compose.ui.node.E e = oVarA.c;
        if (e.F() && e.E()) {
            androidx.compose.ui.geometry.c cVarE = oVarA.e();
            v(new Region(Math.round(cVarE.a), Math.round(cVarE.b), Math.round(cVarE.c), Math.round(cVarE.d)), oVarA, c0223v2, oVarA, new Region());
        }
        return c0223v2;
    }

    public static final void v(Region region, androidx.compose.ui.semantics.o oVar, C0223v c0223v, androidx.compose.ui.semantics.o oVar2, Region region2) {
        androidx.compose.ui.node.E e;
        InterfaceC0917m interfaceC0917mE;
        boolean zF = oVar2.c.F();
        androidx.compose.ui.node.E e2 = oVar2.c;
        boolean z = (zF && e2.E()) ? false : true;
        boolean zIsEmpty = region.isEmpty();
        int i = oVar.g;
        int i2 = oVar2.g;
        if (!zIsEmpty || i2 == i) {
            if (!z || oVar2.e) {
                androidx.compose.ui.semantics.k kVar = oVar2.d;
                boolean z2 = kVar.b;
                InterfaceC0917m interfaceC0917m = oVar2.a;
                if (z2 && (interfaceC0917mE = AbstractC3142f5.e(e2)) != null) {
                    interfaceC0917m = interfaceC0917mE;
                }
                androidx.compose.ui.p pVar = ((androidx.compose.ui.p) interfaceC0917m).a;
                Object obj = kVar.a.get(androidx.compose.ui.semantics.j.b);
                if (obj == null) {
                    obj = null;
                }
                boolean z3 = obj != null;
                boolean z4 = pVar.a.m;
                androidx.compose.ui.geometry.c cVar = androidx.compose.ui.geometry.c.e;
                if (z4) {
                    if (z3) {
                        androidx.compose.ui.node.a0 a0VarT = AbstractC0910f.t(pVar, 8);
                        if (a0VarT.W0().m) {
                            androidx.compose.ui.layout.r rVarG = AbstractC0897s.g(a0VarT);
                            androidx.camera.camera2.internal.q0 q0Var = a0VarT.y;
                            if (q0Var == null) {
                                q0Var = new androidx.camera.camera2.internal.q0();
                                q0Var.b = DefinitionKt.NO_Float_VALUE;
                                q0Var.c = DefinitionKt.NO_Float_VALUE;
                                q0Var.d = DefinitionKt.NO_Float_VALUE;
                                q0Var.e = DefinitionKt.NO_Float_VALUE;
                                a0VarT.y = q0Var;
                            }
                            long jM0 = a0VarT.M0(a0VarT.V0());
                            q0Var.b = -androidx.compose.ui.geometry.e.d(jM0);
                            q0Var.c = -androidx.compose.ui.geometry.e.b(jM0);
                            q0Var.d = androidx.compose.ui.geometry.e.d(jM0) + a0VarT.k0();
                            q0Var.e = androidx.compose.ui.geometry.e.b(jM0) + a0VarT.i0();
                            while (true) {
                                if (a0VarT == rVarG) {
                                    cVar = new androidx.compose.ui.geometry.c(q0Var.b, q0Var.c, q0Var.d, q0Var.e);
                                    break;
                                }
                                a0VarT.k1(q0Var, false, true);
                                if (q0Var.f()) {
                                    break;
                                }
                                a0VarT = a0VarT.n;
                                Intrinsics.d(a0VarT);
                            }
                        }
                    } else {
                        androidx.compose.ui.node.a0 a0VarT2 = AbstractC0910f.t(pVar, 8);
                        cVar = AbstractC0897s.g(a0VarT2).o(a0VarT2, true);
                    }
                }
                int iRound = Math.round(cVar.a);
                int iRound2 = Math.round(cVar.b);
                int iRound3 = Math.round(cVar.c);
                int iRound4 = Math.round(cVar.d);
                region2.set(iRound, iRound2, iRound3, iRound4);
                if (i2 == i) {
                    i2 = -1;
                }
                if (!region2.op(region, Region.Op.INTERSECT)) {
                    if (oVar2.e) {
                        androidx.compose.ui.semantics.o oVarJ = oVar2.j();
                        androidx.compose.ui.geometry.c cVarE = (oVarJ == null || (e = oVarJ.c) == null || !e.F()) ? c : oVarJ.e();
                        c0223v.h(i2, new P0(oVar2, new Rect(Math.round(cVarE.a), Math.round(cVarE.b), Math.round(cVarE.c), Math.round(cVarE.d))));
                        return;
                    } else {
                        if (i2 == -1) {
                            c0223v.h(i2, new P0(oVar2, region2.getBounds()));
                            return;
                        }
                        return;
                    }
                }
                c0223v.h(i2, new P0(oVar2, region2.getBounds()));
                List listH = androidx.compose.ui.semantics.o.h(oVar2, 4);
                for (int size = listH.size() - 1; -1 < size; size--) {
                    v(region, oVar, c0223v, (androidx.compose.ui.semantics.o) listH.get(size), region2);
                }
                if (y(oVar2)) {
                    region.op(iRound, iRound2, iRound3, iRound4, Region.Op.DIFFERENCE);
                }
            }
        }
    }

    public static final androidx.compose.ui.text.H w(androidx.compose.ui.semantics.k kVar) {
        Function1 function1;
        ArrayList arrayList = new ArrayList();
        Object obj = kVar.a.get(androidx.compose.ui.semantics.j.a);
        if (obj == null) {
            obj = null;
        }
        androidx.compose.ui.semantics.a aVar = (androidx.compose.ui.semantics.a) obj;
        if (aVar == null || (function1 = (Function1) aVar.b) == null || !((Boolean) function1.invoke(arrayList)).booleanValue()) {
            return null;
        }
        return (androidx.compose.ui.text.H) arrayList.get(0);
    }

    public static final boolean x(float[] fArr, float[] fArr2) {
        float f = fArr[0];
        float f2 = fArr[1];
        float f3 = fArr[2];
        float f4 = fArr[3];
        float f5 = fArr[4];
        float f6 = fArr[5];
        float f7 = fArr[6];
        float f8 = fArr[7];
        float f9 = fArr[8];
        float f10 = fArr[9];
        float f11 = fArr[10];
        float f12 = fArr[11];
        float f13 = fArr[12];
        float f14 = fArr[13];
        float f15 = fArr[14];
        float f16 = fArr[15];
        float f17 = (f * f6) - (f2 * f5);
        float f18 = (f * f7) - (f3 * f5);
        float f19 = (f * f8) - (f4 * f5);
        float f20 = (f2 * f7) - (f3 * f6);
        float f21 = (f2 * f8) - (f4 * f6);
        float f22 = (f3 * f8) - (f4 * f7);
        float f23 = (f9 * f14) - (f10 * f13);
        float f24 = (f9 * f15) - (f11 * f13);
        float f25 = (f9 * f16) - (f12 * f13);
        float f26 = (f10 * f15) - (f11 * f14);
        float f27 = (f10 * f16) - (f12 * f14);
        float f28 = (f11 * f16) - (f12 * f15);
        float f29 = (f22 * f23) + (((f20 * f25) + ((f19 * f26) + ((f17 * f28) - (f18 * f27)))) - (f21 * f24));
        if (f29 == DefinitionKt.NO_Float_VALUE) {
            return false;
        }
        float f30 = 1.0f / f29;
        fArr2[0] = ((f8 * f26) + ((f6 * f28) - (f7 * f27))) * f30;
        fArr2[1] = (((f3 * f27) + ((-f2) * f28)) - (f4 * f26)) * f30;
        fArr2[2] = ((f16 * f20) + ((f14 * f22) - (f15 * f21))) * f30;
        fArr2[3] = (((f11 * f21) + ((-f10) * f22)) - (f12 * f20)) * f30;
        float f31 = -f5;
        fArr2[4] = (((f7 * f25) + (f31 * f28)) - (f8 * f24)) * f30;
        fArr2[5] = ((f4 * f24) + ((f28 * f) - (f3 * f25))) * f30;
        float f32 = -f13;
        fArr2[6] = (((f15 * f19) + (f32 * f22)) - (f16 * f18)) * f30;
        fArr2[7] = ((f12 * f18) + ((f22 * f9) - (f11 * f19))) * f30;
        fArr2[8] = ((f8 * f23) + ((f5 * f27) - (f6 * f25))) * f30;
        fArr2[9] = (((f25 * f2) + ((-f) * f27)) - (f4 * f23)) * f30;
        fArr2[10] = ((f16 * f17) + ((f13 * f21) - (f14 * f19))) * f30;
        fArr2[11] = (((f19 * f10) + ((-f9) * f21)) - (f12 * f17)) * f30;
        fArr2[12] = (((f6 * f24) + (f31 * f26)) - (f7 * f23)) * f30;
        fArr2[13] = ((f3 * f23) + ((f * f26) - (f2 * f24))) * f30;
        fArr2[14] = (((f14 * f18) + (f32 * f20)) - (f15 * f17)) * f30;
        fArr2[15] = ((f11 * f17) + ((f9 * f20) - (f10 * f18))) * f30;
        return true;
    }

    public static final boolean y(androidx.compose.ui.semantics.o oVar) {
        if (!B(oVar)) {
            return false;
        }
        androidx.compose.ui.semantics.k kVar = oVar.d;
        if (kVar.b) {
            return true;
        }
        Set setKeySet = kVar.a.keySet();
        if ((setKeySet instanceof Collection) && setKeySet.isEmpty()) {
            return false;
        }
        Iterator it2 = setKeySet.iterator();
        while (it2.hasNext()) {
            if (((androidx.compose.ui.semantics.u) it2.next()).c) {
                return true;
            }
        }
        return false;
    }

    public static final boolean z(androidx.compose.ui.graphics.N n, float f, float f2) {
        if (n instanceof androidx.compose.ui.graphics.L) {
            androidx.compose.ui.geometry.c cVar = ((androidx.compose.ui.graphics.L) n).a;
            return cVar.a <= f && f < cVar.c && cVar.b <= f2 && f2 < cVar.d;
        }
        if (!(n instanceof androidx.compose.ui.graphics.M)) {
            if (n instanceof androidx.compose.ui.graphics.K) {
                return A(((androidx.compose.ui.graphics.K) n).a, f, f2);
            }
            throw new NoWhenBranchMatchedException();
        }
        androidx.compose.ui.geometry.d dVar = ((androidx.compose.ui.graphics.M) n).a;
        float f3 = dVar.a;
        if (f < f3) {
            return false;
        }
        float f4 = dVar.c;
        if (f >= f4) {
            return false;
        }
        float f5 = dVar.b;
        if (f2 < f5) {
            return false;
        }
        float f6 = dVar.d;
        if (f2 >= f6) {
            return false;
        }
        long j = dVar.e;
        float fB = androidx.compose.ui.geometry.a.b(j);
        long j2 = dVar.f;
        if (androidx.compose.ui.geometry.a.b(j2) + fB <= dVar.b()) {
            long j3 = dVar.h;
            float fB2 = androidx.compose.ui.geometry.a.b(j3);
            long j4 = dVar.g;
            if (androidx.compose.ui.geometry.a.b(j4) + fB2 <= dVar.b()) {
                if (androidx.compose.ui.geometry.a.c(j3) + androidx.compose.ui.geometry.a.c(j) <= dVar.a()) {
                    if (androidx.compose.ui.geometry.a.c(j4) + androidx.compose.ui.geometry.a.c(j2) <= dVar.a()) {
                        float fB3 = androidx.compose.ui.geometry.a.b(j) + f3;
                        float fC = androidx.compose.ui.geometry.a.c(j) + f5;
                        float fB4 = f4 - androidx.compose.ui.geometry.a.b(j2);
                        float fC2 = androidx.compose.ui.geometry.a.c(j2) + f5;
                        float fB5 = f4 - androidx.compose.ui.geometry.a.b(j4);
                        float fC3 = f6 - androidx.compose.ui.geometry.a.c(j4);
                        float fC4 = f6 - androidx.compose.ui.geometry.a.c(j3);
                        float fB6 = androidx.compose.ui.geometry.a.b(j3) + f3;
                        if (f < fB3 && f2 < fC) {
                            return C(f, f2, dVar.e, fB3, fC);
                        }
                        if (f < fB6 && f2 > fC4) {
                            return C(f, f2, dVar.h, fB6, fC4);
                        }
                        if (f > fB4 && f2 < fC2) {
                            return C(f, f2, dVar.f, fB4, fC2);
                        }
                        if (f <= fB5 || f2 <= fC3) {
                            return true;
                        }
                        return C(f, f2, dVar.g, fB5, fC3);
                    }
                }
            }
        }
        C0850j c0850jH = androidx.compose.ui.graphics.F.h();
        androidx.compose.ui.graphics.O.b(c0850jH, dVar);
        return A(c0850jH, f, f2);
    }
}
