package androidx.compose.runtime.changelist;

import androidx.compose.runtime.C0774b;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0836x0;
import androidx.compose.runtime.D0;
import androidx.compose.runtime.InterfaceC0790d;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final class r extends J {
    public static final r e;
    public static final r g;
    public final /* synthetic */ int c;
    public static final r d = new r(1, 2, 0);
    public static final r f = new r(1, 2, 2);

    static {
        int i = 1;
        e = new r(i, i, 1);
        int i2 = 1;
        g = new r(i2, i2, 3);
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ r(int i, int i2, int i3) {
        super(i, i2);
        this.c = i3;
    }

    @Override // androidx.compose.runtime.changelist.J
    public final void a(K k, InterfaceC0790d interfaceC0790d, D0 d0, androidx.compose.runtime.internal.j jVar) {
        int iC;
        int iO;
        switch (this.c) {
            case 0:
                Object objInvoke = ((Function0) k.f(0)).invoke();
                C0774b c0774b = (C0774b) k.f(1);
                int iE = k.e(0);
                c0774b.getClass();
                d0.V(d0.c(c0774b), objInvoke);
                interfaceC0790d.i(iE, objInvoke);
                interfaceC0790d.d(objInvoke);
                break;
            case 1:
                C0774b c0774b2 = (C0774b) k.f(0);
                int iE2 = k.e(0);
                interfaceC0790d.h();
                c0774b2.getClass();
                interfaceC0790d.c(iE2, d0.C(d0.c(c0774b2)));
                break;
            case 2:
                Object objF = k.f(0);
                C0774b c0774b3 = (C0774b) k.f(1);
                int iE3 = k.e(0);
                if (objF instanceof C0836x0) {
                    ((androidx.compose.runtime.collection.b) jVar.c).b((C0836x0) objF);
                }
                int iC2 = d0.c(c0774b3);
                int iG = d0.g(d0.N(iC2, iE3));
                Object[] objArr = d0.c;
                Object obj = objArr[iG];
                objArr[iG] = objF;
                if (!(obj instanceof C0836x0)) {
                    if (obj instanceof C0813o0) {
                        ((C0813o0) obj).d();
                        break;
                    }
                } else {
                    int iO2 = d0.o() - d0.N(iC2, iE3);
                    C0836x0 c0836x0 = (C0836x0) obj;
                    C0774b c0774b4 = c0836x0.b;
                    if (c0774b4 == null || !c0774b4.a()) {
                        iC = -1;
                        iO = -1;
                    } else {
                        iC = d0.c(c0774b4);
                        iO = d0.o() - d0.O(iC);
                    }
                    jVar.w(c0836x0, iO2, iC, iO);
                    break;
                }
                break;
            default:
                Object objF2 = k.f(0);
                int iE4 = k.e(0);
                if (objF2 instanceof C0836x0) {
                    ((androidx.compose.runtime.collection.b) jVar.c).b((C0836x0) objF2);
                }
                int iG2 = d0.g(d0.N(d0.t, iE4));
                Object[] objArr2 = d0.c;
                Object obj2 = objArr2[iG2];
                objArr2[iG2] = objF2;
                if (!(obj2 instanceof C0836x0)) {
                    if (obj2 instanceof C0813o0) {
                        ((C0813o0) obj2).d();
                        break;
                    }
                } else {
                    jVar.w((C0836x0) obj2, d0.o() - d0.N(d0.t, iE4), -1, -1);
                    break;
                }
                break;
        }
    }
}
