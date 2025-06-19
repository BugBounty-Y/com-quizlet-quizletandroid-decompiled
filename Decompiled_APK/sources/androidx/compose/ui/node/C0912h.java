package androidx.compose.ui.node;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0837y;
import androidx.compose.runtime.X0;
import androidx.compose.ui.platform.AbstractC0955m0;
import androidx.compose.ui.platform.Y0;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.ui.node.h, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0912h extends kotlin.jvm.internal.r implements Function2 {
    public static final C0912h b = new C0912h(2, 0);
    public static final C0912h c = new C0912h(2, 1);
    public static final C0912h d = new C0912h(2, 2);
    public static final C0912h e = new C0912h(2, 3);
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C0912h(int i, int i2) {
        super(i);
        this.a = i2;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r1v1 */
    /* JADX WARN: Type inference failed for: r1v10 */
    /* JADX WARN: Type inference failed for: r1v11 */
    /* JADX WARN: Type inference failed for: r1v12 */
    /* JADX WARN: Type inference failed for: r1v2, types: [androidx.compose.ui.p] */
    /* JADX WARN: Type inference failed for: r1v20 */
    /* JADX WARN: Type inference failed for: r1v21 */
    /* JADX WARN: Type inference failed for: r1v6 */
    /* JADX WARN: Type inference failed for: r1v7, types: [androidx.compose.ui.p] */
    /* JADX WARN: Type inference failed for: r1v8, types: [java.lang.Object] */
    /* JADX WARN: Type inference failed for: r1v9 */
    /* JADX WARN: Type inference failed for: r2v0 */
    /* JADX WARN: Type inference failed for: r2v1 */
    /* JADX WARN: Type inference failed for: r2v11 */
    /* JADX WARN: Type inference failed for: r2v12, types: [androidx.compose.ui.p] */
    /* JADX WARN: Type inference failed for: r2v13, types: [java.lang.Object] */
    /* JADX WARN: Type inference failed for: r2v14 */
    /* JADX WARN: Type inference failed for: r2v15 */
    /* JADX WARN: Type inference failed for: r2v16 */
    /* JADX WARN: Type inference failed for: r2v17 */
    /* JADX WARN: Type inference failed for: r2v18 */
    /* JADX WARN: Type inference failed for: r2v19, types: [androidx.compose.ui.p] */
    /* JADX WARN: Type inference failed for: r2v2 */
    /* JADX WARN: Type inference failed for: r2v22 */
    /* JADX WARN: Type inference failed for: r2v23, types: [androidx.compose.ui.p] */
    /* JADX WARN: Type inference failed for: r2v24, types: [java.lang.Object] */
    /* JADX WARN: Type inference failed for: r2v25 */
    /* JADX WARN: Type inference failed for: r2v26 */
    /* JADX WARN: Type inference failed for: r2v27 */
    /* JADX WARN: Type inference failed for: r2v28 */
    /* JADX WARN: Type inference failed for: r2v29 */
    /* JADX WARN: Type inference failed for: r2v3, types: [androidx.compose.runtime.collection.b] */
    /* JADX WARN: Type inference failed for: r2v30 */
    /* JADX WARN: Type inference failed for: r2v31 */
    /* JADX WARN: Type inference failed for: r2v32 */
    /* JADX WARN: Type inference failed for: r2v33 */
    /* JADX WARN: Type inference failed for: r2v34 */
    /* JADX WARN: Type inference failed for: r2v35 */
    /* JADX WARN: Type inference failed for: r2v36 */
    /* JADX WARN: Type inference failed for: r2v4 */
    /* JADX WARN: Type inference failed for: r2v5 */
    /* JADX WARN: Type inference failed for: r2v6, types: [androidx.compose.runtime.collection.b] */
    /* JADX WARN: Type inference failed for: r2v8 */
    /* JADX WARN: Type inference failed for: r2v9, types: [androidx.compose.ui.p] */
    /* JADX WARN: Type inference failed for: r3v10 */
    /* JADX WARN: Type inference failed for: r3v11 */
    /* JADX WARN: Type inference failed for: r3v12 */
    /* JADX WARN: Type inference failed for: r3v13, types: [androidx.compose.runtime.collection.b] */
    /* JADX WARN: Type inference failed for: r3v14 */
    /* JADX WARN: Type inference failed for: r3v15 */
    /* JADX WARN: Type inference failed for: r3v16, types: [androidx.compose.runtime.collection.b] */
    /* JADX WARN: Type inference failed for: r3v18 */
    /* JADX WARN: Type inference failed for: r3v19 */
    /* JADX WARN: Type inference failed for: r3v20 */
    /* JADX WARN: Type inference failed for: r3v21, types: [androidx.compose.runtime.collection.b] */
    /* JADX WARN: Type inference failed for: r3v22 */
    /* JADX WARN: Type inference failed for: r3v23 */
    /* JADX WARN: Type inference failed for: r3v24, types: [androidx.compose.runtime.collection.b] */
    /* JADX WARN: Type inference failed for: r3v26 */
    /* JADX WARN: Type inference failed for: r3v27 */
    /* JADX WARN: Type inference failed for: r3v28 */
    /* JADX WARN: Type inference failed for: r3v29 */
    /* JADX WARN: Type inference failed for: r3v30 */
    /* JADX WARN: Type inference failed for: r3v31 */
    /* JADX WARN: Type inference failed for: r3v32 */
    /* JADX WARN: Type inference failed for: r3v33 */
    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Number) obj2).intValue();
                ((InterfaceC0915k) obj).getClass();
                break;
            case 1:
                ((E) ((InterfaceC0915k) obj)).Y((androidx.compose.ui.layout.K) obj2);
                break;
            case 2:
                ((E) ((InterfaceC0915k) obj)).Z((androidx.compose.ui.q) obj2);
                break;
            default:
                InterfaceC0837y interfaceC0837y = (InterfaceC0837y) obj2;
                E e2 = (E) ((InterfaceC0915k) obj);
                e2.u = interfaceC0837y;
                X0 x0 = AbstractC0955m0.f;
                androidx.compose.runtime.internal.i iVar = (androidx.compose.runtime.internal.i) interfaceC0837y;
                iVar.getClass();
                e2.W((androidx.compose.ui.unit.b) C0776c.B(iVar, x0));
                androidx.compose.ui.unit.k kVar = (androidx.compose.ui.unit.k) C0776c.B(iVar, AbstractC0955m0.l);
                if (e2.s != kVar) {
                    e2.s = kVar;
                    e2.B();
                    E eS = e2.s();
                    if (eS != null) {
                        eS.z();
                    }
                    e2.A();
                    androidx.compose.ui.p pVar = (androidx.compose.ui.p) e2.w.f;
                    if ((pVar.d & 4) != 0) {
                        while (pVar != null) {
                            if ((pVar.c & 4) != 0) {
                                AbstractC0918n abstractC0918nF = pVar;
                                ?? bVar = 0;
                                while (abstractC0918nF != 0) {
                                    if (abstractC0918nF instanceof InterfaceC0919o) {
                                        InterfaceC0919o interfaceC0919o = (InterfaceC0919o) abstractC0918nF;
                                        if (interfaceC0919o instanceof androidx.compose.ui.draw.c) {
                                            ((androidx.compose.ui.draw.c) interfaceC0919o).M0();
                                        }
                                    } else if ((abstractC0918nF.c & 4) != 0 && (abstractC0918nF instanceof AbstractC0918n)) {
                                        androidx.compose.ui.p pVar2 = abstractC0918nF.o;
                                        int i = 0;
                                        abstractC0918nF = abstractC0918nF;
                                        bVar = bVar;
                                        while (pVar2 != null) {
                                            if ((pVar2.c & 4) != 0) {
                                                i++;
                                                bVar = bVar;
                                                if (i == 1) {
                                                    abstractC0918nF = pVar2;
                                                } else {
                                                    if (bVar == 0) {
                                                        bVar = new androidx.compose.runtime.collection.b(new androidx.compose.ui.p[16]);
                                                    }
                                                    if (abstractC0918nF != 0) {
                                                        bVar.b(abstractC0918nF);
                                                        abstractC0918nF = 0;
                                                    }
                                                    bVar.b(pVar2);
                                                }
                                            }
                                            pVar2 = pVar2.f;
                                            abstractC0918nF = abstractC0918nF;
                                            bVar = bVar;
                                        }
                                        if (i == 1) {
                                        }
                                    }
                                    abstractC0918nF = AbstractC0910f.f(bVar);
                                }
                            }
                            if ((pVar.d & 4) != 0) {
                                pVar = pVar.f;
                            }
                        }
                    }
                }
                Y0 y0 = (Y0) C0776c.B(iVar, AbstractC0955m0.q);
                if (!Intrinsics.b(e2.t, y0)) {
                    e2.t = y0;
                    androidx.compose.ui.p pVar3 = (androidx.compose.ui.p) e2.w.f;
                    if ((pVar3.d & 16) != 0) {
                        while (pVar3 != null) {
                            if ((pVar3.c & 16) != 0) {
                                AbstractC0918n abstractC0918nF2 = pVar3;
                                ?? bVar2 = 0;
                                while (abstractC0918nF2 != 0) {
                                    if (abstractC0918nF2 instanceof l0) {
                                        ((l0) abstractC0918nF2).t0();
                                    } else if ((abstractC0918nF2.c & 16) != 0 && (abstractC0918nF2 instanceof AbstractC0918n)) {
                                        androidx.compose.ui.p pVar4 = abstractC0918nF2.o;
                                        int i2 = 0;
                                        abstractC0918nF2 = abstractC0918nF2;
                                        bVar2 = bVar2;
                                        while (pVar4 != null) {
                                            if ((pVar4.c & 16) != 0) {
                                                i2++;
                                                bVar2 = bVar2;
                                                if (i2 == 1) {
                                                    abstractC0918nF2 = pVar4;
                                                } else {
                                                    if (bVar2 == 0) {
                                                        bVar2 = new androidx.compose.runtime.collection.b(new androidx.compose.ui.p[16]);
                                                    }
                                                    if (abstractC0918nF2 != 0) {
                                                        bVar2.b(abstractC0918nF2);
                                                        abstractC0918nF2 = 0;
                                                    }
                                                    bVar2.b(pVar4);
                                                }
                                            }
                                            pVar4 = pVar4.f;
                                            abstractC0918nF2 = abstractC0918nF2;
                                            bVar2 = bVar2;
                                        }
                                        if (i2 == 1) {
                                        }
                                    }
                                    abstractC0918nF2 = AbstractC0910f.f(bVar2);
                                }
                            }
                            if ((pVar3.d & 16) != 0) {
                                pVar3 = pVar3.f;
                            }
                        }
                    }
                }
                androidx.compose.ui.p pVar5 = (androidx.compose.ui.p) e2.w.f;
                if ((pVar5.d & 32768) != 0) {
                    while (pVar5 != null) {
                        if ((pVar5.c & 32768) != 0) {
                            AbstractC0918n abstractC0918nF3 = pVar5;
                            ?? bVar3 = 0;
                            while (abstractC0918nF3 != 0) {
                                if (abstractC0918nF3 instanceof InterfaceC0916l) {
                                    androidx.compose.ui.p pVar6 = ((androidx.compose.ui.p) ((InterfaceC0916l) abstractC0918nF3)).a;
                                    if (pVar6.m) {
                                        b0.d(pVar6);
                                    } else {
                                        pVar6.j = true;
                                    }
                                } else if ((abstractC0918nF3.c & 32768) != 0 && (abstractC0918nF3 instanceof AbstractC0918n)) {
                                    androidx.compose.ui.p pVar7 = abstractC0918nF3.o;
                                    int i3 = 0;
                                    abstractC0918nF3 = abstractC0918nF3;
                                    bVar3 = bVar3;
                                    while (pVar7 != null) {
                                        if ((pVar7.c & 32768) != 0) {
                                            i3++;
                                            bVar3 = bVar3;
                                            if (i3 == 1) {
                                                abstractC0918nF3 = pVar7;
                                            } else {
                                                if (bVar3 == 0) {
                                                    bVar3 = new androidx.compose.runtime.collection.b(new androidx.compose.ui.p[16]);
                                                }
                                                if (abstractC0918nF3 != 0) {
                                                    bVar3.b(abstractC0918nF3);
                                                    abstractC0918nF3 = 0;
                                                }
                                                bVar3.b(pVar7);
                                            }
                                        }
                                        pVar7 = pVar7.f;
                                        abstractC0918nF3 = abstractC0918nF3;
                                        bVar3 = bVar3;
                                    }
                                    if (i3 == 1) {
                                    }
                                }
                                abstractC0918nF3 = AbstractC0910f.f(bVar3);
                            }
                        }
                        if ((pVar5.d & 32768) != 0) {
                            pVar5 = pVar5.f;
                        }
                    }
                }
                break;
        }
        return Unit.a;
    }
}
