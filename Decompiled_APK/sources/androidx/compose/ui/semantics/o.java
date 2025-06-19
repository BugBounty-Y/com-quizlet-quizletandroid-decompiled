package androidx.compose.ui.semantics;

import androidx.compose.foundation.C0367i0;
import androidx.compose.runtime.C0775b0;
import androidx.compose.ui.layout.AbstractC0897s;
import androidx.compose.ui.node.AbstractC0910f;
import androidx.compose.ui.node.E;
import androidx.compose.ui.node.InterfaceC0917m;
import androidx.compose.ui.node.a0;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3142f5;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import kotlin.collections.CollectionsKt;
import kotlin.collections.K;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class o {
    public final androidx.compose.ui.p a;
    public final boolean b;
    public final E c;
    public final k d;
    public boolean e;
    public o f;
    public final int g;

    public o(androidx.compose.ui.p pVar, boolean z, E e, k kVar) {
        this.a = pVar;
        this.b = z;
        this.c = e;
        this.d = kVar;
        this.g = e.b;
    }

    public static /* synthetic */ List h(o oVar, int i) {
        return oVar.g((i & 1) != 0 ? !oVar.b : false, (i & 2) == 0);
    }

    public final o a(h hVar, Function1 function1) {
        k kVar = new k();
        kVar.b = false;
        kVar.c = false;
        function1.invoke(kVar);
        o oVar = new o(new n(function1), false, new E(true, this.g + (hVar != null ? 1000000000 : 2000000000)), kVar);
        oVar.e = true;
        oVar.f = this;
        return oVar;
    }

    public final void b(E e, ArrayList arrayList) {
        androidx.compose.runtime.collection.b bVarV = e.v();
        int i = bVarV.c;
        if (i > 0) {
            Object[] objArr = bVarV.a;
            int i2 = 0;
            do {
                E e2 = (E) objArr[i2];
                if (e2.E() && !e2.G) {
                    if (e2.w.h(8)) {
                        arrayList.add(AbstractC3142f5.d(e2, this.b));
                    } else {
                        b(e2, arrayList);
                    }
                }
                i2++;
            } while (i2 < i);
        }
    }

    public final a0 c() {
        if (this.e) {
            o oVarJ = j();
            if (oVarJ != null) {
                return oVarJ.c();
            }
            return null;
        }
        InterfaceC0917m interfaceC0917mE = AbstractC3142f5.e(this.c);
        if (interfaceC0917mE == null) {
            interfaceC0917mE = this.a;
        }
        return AbstractC0910f.t(interfaceC0917mE, 8);
    }

    public final void d(ArrayList arrayList) {
        List listO = o(false);
        int size = listO.size();
        for (int i = 0; i < size; i++) {
            o oVar = (o) listO.get(i);
            if (oVar.l()) {
                arrayList.add(oVar);
            } else if (!oVar.d.c) {
                oVar.d(arrayList);
            }
        }
    }

    public final androidx.compose.ui.geometry.c e() {
        a0 a0VarC = c();
        if (a0VarC != null) {
            if (!a0VarC.W0().m) {
                a0VarC = null;
            }
            if (a0VarC != null) {
                return AbstractC0897s.g(a0VarC).o(a0VarC, true);
            }
        }
        return androidx.compose.ui.geometry.c.e;
    }

    public final androidx.compose.ui.geometry.c f() {
        a0 a0VarC = c();
        if (a0VarC != null) {
            if (!a0VarC.W0().m) {
                a0VarC = null;
            }
            if (a0VarC != null) {
                return AbstractC0897s.f(a0VarC);
            }
        }
        return androidx.compose.ui.geometry.c.e;
    }

    public final List g(boolean z, boolean z2) {
        if (!z && this.d.c) {
            return K.a;
        }
        if (!l()) {
            return o(z2);
        }
        ArrayList arrayList = new ArrayList();
        d(arrayList);
        return arrayList;
    }

    public final k i() {
        boolean zL = l();
        k kVar = this.d;
        if (!zL) {
            return kVar;
        }
        k kVar2 = new k();
        kVar2.b = kVar.b;
        kVar2.c = kVar.c;
        kVar2.a.putAll(kVar.a);
        n(kVar2);
        return kVar2;
    }

    public final o j() {
        E eS;
        o oVar = this.f;
        if (oVar != null) {
            return oVar;
        }
        E e = this.c;
        boolean z = this.b;
        if (z) {
            eS = e.s();
            while (eS != null) {
                k kVarO = eS.o();
                if (kVarO != null && kVarO.b) {
                    break;
                }
                eS = eS.s();
            }
            eS = null;
        } else {
            eS = null;
        }
        if (eS == null) {
            E eS2 = e.s();
            while (true) {
                if (eS2 == null) {
                    eS = null;
                    break;
                }
                if (eS2.w.h(8)) {
                    eS = eS2;
                    break;
                }
                eS2 = eS2.s();
            }
        }
        if (eS == null) {
            return null;
        }
        return AbstractC3142f5.d(eS, z);
    }

    public final k k() {
        return this.d;
    }

    public final boolean l() {
        return this.b && this.d.b;
    }

    public final boolean m() {
        if (this.e || !h(this, 4).isEmpty()) {
            return false;
        }
        E eS = this.c.s();
        while (true) {
            if (eS == null) {
                eS = null;
                break;
            }
            k kVarO = eS.o();
            if (kVarO != null && kVarO.b) {
                break;
            }
            eS = eS.s();
        }
        return eS == null;
    }

    public final void n(k kVar) {
        if (this.d.c) {
            return;
        }
        List listO = o(false);
        int size = listO.size();
        for (int i = 0; i < size; i++) {
            o oVar = (o) listO.get(i);
            if (!oVar.l()) {
                for (Map.Entry entry : oVar.d.a.entrySet()) {
                    u uVar = (u) entry.getKey();
                    Object value = entry.getValue();
                    LinkedHashMap linkedHashMap = kVar.a;
                    Object obj = linkedHashMap.get(uVar);
                    Intrinsics.e(uVar, "null cannot be cast to non-null type androidx.compose.ui.semantics.SemanticsPropertyKey<kotlin.Any?>");
                    Object objInvoke = uVar.b.invoke(obj, value);
                    if (objInvoke != null) {
                        linkedHashMap.put(uVar, objInvoke);
                    }
                }
                oVar.n(kVar);
            }
        }
    }

    public final List o(boolean z) {
        if (this.e) {
            return K.a;
        }
        ArrayList arrayList = new ArrayList();
        b(this.c, arrayList);
        if (z) {
            u uVar = r.s;
            k kVar = this.d;
            LinkedHashMap linkedHashMap = kVar.a;
            Object obj = linkedHashMap.get(uVar);
            if (obj == null) {
                obj = null;
            }
            h hVar = (h) obj;
            if (hVar != null && kVar.b && !arrayList.isEmpty()) {
                arrayList.add(a(hVar, new C0775b0(hVar, 23)));
            }
            u uVar2 = r.a;
            if (linkedHashMap.containsKey(uVar2) && !arrayList.isEmpty() && kVar.b) {
                Object obj2 = linkedHashMap.get(uVar2);
                if (obj2 == null) {
                    obj2 = null;
                }
                List list = (List) obj2;
                String str = list != null ? (String) CollectionsKt.firstOrNull(list) : null;
                if (str != null) {
                    arrayList.add(0, a(null, new C0367i0(str, 10)));
                }
            }
        }
        return arrayList;
    }
}
