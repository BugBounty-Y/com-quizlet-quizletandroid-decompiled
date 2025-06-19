package androidx.camera.camera2.internal;

import androidx.compose.ui.text.C0995g;
import androidx.transition.InterfaceC1419w;
import com.comscore.streaming.EventType;
import com.facebook.internal.C1563s;
import com.facebook.internal.EnumC1562q;
import com.facebook.internal.InterfaceC1561p;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONArray;

/* loaded from: classes.dex */
public final /* synthetic */ class s0 implements androidx.arch.core.util.a, androidx.compose.animation.core.B, androidx.compose.ui.graphics.colorspace.i, androidx.compose.ui.text.input.K, androidx.transition.x, InterfaceC1561p {
    public final /* synthetic */ int a;

    public /* synthetic */ s0(int i) {
        this.a = i;
    }

    @Override // androidx.transition.x
    public void a(InterfaceC1419w interfaceC1419w, androidx.transition.y yVar, boolean z) {
        switch (this.a) {
            case 14:
                interfaceC1419w.c(yVar);
                break;
            case 15:
                interfaceC1419w.e(yVar);
                break;
            case 16:
                interfaceC1419w.f(yVar);
                break;
            case 17:
                interfaceC1419w.a();
                break;
            default:
                interfaceC1419w.g();
                break;
        }
    }

    @Override // androidx.arch.core.util.a
    /* renamed from: apply */
    public Object mo0apply(Object obj) {
        List list = (List) obj;
        switch (this.a) {
            case 1:
                return null;
            default:
                if (list == null) {
                    return null;
                }
                ArrayList arrayList = new ArrayList(kotlin.collections.C.q(list, 10));
                Iterator it2 = list.iterator();
                while (it2.hasNext()) {
                    arrayList.add(((androidx.work.impl.model.p) it2.next()).a());
                }
                return arrayList;
        }
    }

    @Override // androidx.compose.animation.core.B
    public float b(float f) {
        return f;
    }

    @Override // com.facebook.internal.InterfaceC1561p
    public void c(boolean z) {
        HashSet hashSet;
        switch (this.a) {
            case 21:
                com.facebook.o oVar = com.facebook.o.a;
                if (z && com.facebook.B.c()) {
                    C1563s.a(new com.facebook.appevents.k(13), EnumC1562q.CrashReport);
                    C1563s.a(new com.facebook.appevents.k(14), EnumC1562q.ErrorReport);
                    C1563s.a(new com.facebook.appevents.k(15), EnumC1562q.AnrReport);
                    break;
                }
                break;
            case EventType.WINDOW_STATE /* 22 */:
                com.facebook.o oVar2 = com.facebook.o.a;
                if (z && !com.facebook.internal.instrument.crashshield.a.b(com.facebook.appevents.m.class)) {
                    try {
                        com.facebook.appevents.l callback = new com.facebook.appevents.l();
                        com.facebook.internal.y yVar = com.facebook.internal.y.a;
                        Intrinsics.checkNotNullParameter(callback, "callback");
                        com.facebook.internal.y.e.add(callback);
                        com.facebook.internal.y.d();
                        break;
                    } catch (Throwable th) {
                        com.facebook.internal.instrument.crashshield.a.a(com.facebook.appevents.m.class, th);
                        return;
                    }
                }
                break;
            case EventType.AUDIO /* 23 */:
                if (!z) {
                    com.facebook.o oVar3 = com.facebook.o.a;
                    break;
                } else {
                    com.facebook.o.l = true;
                    break;
                }
            case EventType.VIDEO /* 24 */:
                if (!z) {
                    com.facebook.o oVar4 = com.facebook.o.a;
                    break;
                } else {
                    com.facebook.o.m = true;
                    break;
                }
            case EventType.SUBS /* 25 */:
                if (!z) {
                    com.facebook.o oVar5 = com.facebook.o.a;
                    break;
                } else {
                    com.facebook.o.n = true;
                    break;
                }
            case EventType.CDN /* 26 */:
                if (z) {
                    Object obj = com.facebook.appevents.aam.a.class;
                    try {
                        if (!com.facebook.internal.instrument.crashshield.a.b(obj)) {
                            try {
                                com.facebook.o.c().execute(new RunnableC0131h(8));
                            } catch (Exception unused) {
                                obj = com.facebook.o.a;
                            }
                            break;
                        }
                    } catch (Throwable th2) {
                        com.facebook.internal.instrument.crashshield.a.a(obj, th2);
                        return;
                    }
                }
                break;
            case 27:
                if (z) {
                    com.facebook.appevents.integrity.a aVar = com.facebook.appevents.integrity.a.a;
                    if (!com.facebook.internal.instrument.crashshield.a.b(com.facebook.appevents.integrity.a.class)) {
                        try {
                            if (!com.facebook.appevents.integrity.a.b) {
                                com.facebook.appevents.integrity.a aVar2 = com.facebook.appevents.integrity.a.a;
                                if (!com.facebook.internal.instrument.crashshield.a.b(aVar2)) {
                                    try {
                                        com.facebook.internal.v vVarK = com.facebook.internal.y.k(com.facebook.o.b(), false);
                                        if (vVarK != null) {
                                            JSONArray jSONArray = vVarK.s;
                                            HashSet hashSet2 = null;
                                            try {
                                                if (!com.facebook.internal.instrument.crashshield.a.b(aVar2)) {
                                                    try {
                                                        hashSet = com.facebook.internal.J.f(jSONArray);
                                                        if (hashSet == null) {
                                                            hashSet = new HashSet();
                                                        }
                                                    } catch (Exception unused2) {
                                                        hashSet = new HashSet();
                                                    }
                                                    hashSet2 = hashSet;
                                                }
                                            } catch (Throwable th3) {
                                                com.facebook.internal.instrument.crashshield.a.a(aVar2, th3);
                                            }
                                            com.facebook.appevents.integrity.a.c = hashSet2;
                                        }
                                    } catch (Throwable th4) {
                                        com.facebook.internal.instrument.crashshield.a.a(aVar2, th4);
                                    }
                                }
                                com.facebook.appevents.integrity.a.b = !com.facebook.appevents.integrity.a.c.isEmpty();
                                break;
                            } else {
                                break;
                            }
                        } catch (Throwable th5) {
                            com.facebook.internal.instrument.crashshield.a.a(com.facebook.appevents.integrity.a.class, th5);
                            return;
                        }
                    }
                }
                break;
            case 28:
                if (z) {
                    com.facebook.appevents.iap.q qVar = com.facebook.appevents.iap.q.a;
                    if (!com.facebook.internal.instrument.crashshield.a.b(com.facebook.appevents.iap.q.class)) {
                        try {
                            if (com.facebook.appevents.internal.j.c()) {
                                com.facebook.appevents.iap.q.e.set(true);
                                com.facebook.appevents.iap.q.d();
                            } else {
                                com.facebook.appevents.iap.p.l();
                            }
                            break;
                        } catch (Throwable th6) {
                            com.facebook.internal.instrument.crashshield.a.a(com.facebook.appevents.iap.q.class, th6);
                            return;
                        }
                    }
                }
                break;
            default:
                if (z) {
                    com.facebook.appevents.integrity.i iVar = com.facebook.appevents.integrity.i.a;
                    if (!com.facebook.internal.instrument.crashshield.a.b(com.facebook.appevents.integrity.i.class)) {
                        try {
                            if (!com.facebook.appevents.integrity.i.b) {
                                com.facebook.appevents.integrity.i iVar2 = com.facebook.appevents.integrity.i.a;
                                if (!com.facebook.internal.instrument.crashshield.a.b(iVar2)) {
                                    try {
                                        com.facebook.internal.v vVarK2 = com.facebook.internal.y.k(com.facebook.o.b(), false);
                                        if (vVarK2 != null) {
                                            iVar2.a(vVarK2.r);
                                        }
                                    } catch (Throwable th7) {
                                        com.facebook.internal.instrument.crashshield.a.a(iVar2, th7);
                                    }
                                }
                                com.facebook.appevents.integrity.i.b = (com.facebook.appevents.integrity.i.c.isEmpty() && com.facebook.appevents.integrity.i.d.isEmpty()) ? false : true;
                                break;
                            } else {
                                break;
                            }
                        } catch (Throwable th8) {
                            com.facebook.internal.instrument.crashshield.a.a(com.facebook.appevents.integrity.i.class, th8);
                        }
                    }
                }
                break;
        }
    }

    @Override // androidx.compose.ui.graphics.colorspace.i
    public double d(double d) {
        double d2;
        switch (this.a) {
            case 5:
                double dPow = d < 0.0d ? -d : d;
                if (dPow >= 0.0031308049535603718d) {
                    dPow = Math.pow(dPow, 0.4166666666666667d) - 0.05213270142180095d;
                    d2 = 0.9478672985781991d;
                } else {
                    d2 = 0.07739938080495357d;
                }
                return Math.copySign(dPow / d2, d);
            case 6:
                double d3 = d < 0.0d ? -d : d;
                return Math.copySign(d3 >= 0.04045d ? Math.pow((0.9478672985781991d * d3) + 0.05213270142180095d, 2.4d) : d3 * 0.07739938080495357d, d);
            default:
                return d;
        }
    }

    @Override // androidx.compose.ui.text.input.K
    public androidx.compose.ui.text.input.I e(C0995g c0995g) {
        return new androidx.compose.ui.text.input.I(c0995g, androidx.compose.ui.text.input.r.a);
    }
}
