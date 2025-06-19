package com.airbnb.lottie.parser;

import android.graphics.Rect;
import androidx.collection.C0219q;
import androidx.collection.W;
import com.skydoves.balloon.internals.DefinitionKt;
import java.io.EOFException;
import java.util.ArrayList;
import java.util.HashMap;

/* loaded from: classes.dex */
public abstract class s {
    public static final com.airbnb.lottie.parser.moshi.c a = com.airbnb.lottie.parser.moshi.c.a("w", "h", "ip", "op", "fr", "v", "layers", "assets", "fonts", "chars", "markers");
    public static final com.airbnb.lottie.parser.moshi.c b = com.airbnb.lottie.parser.moshi.c.a("id", "layers", "w", "h", "p", "u");
    public static final com.airbnb.lottie.parser.moshi.c c = com.airbnb.lottie.parser.moshi.c.a("list");
    public static final com.airbnb.lottie.parser.moshi.c d = com.airbnb.lottie.parser.moshi.c.a("cm", "tm", "dr");

    /* JADX WARN: Failed to find 'out' block for switch in B:6:0x0047. Please report as an issue. */
    public static com.airbnb.lottie.h a(com.airbnb.lottie.parser.moshi.e eVar) throws NumberFormatException, EOFException, com.airbnb.lottie.parser.moshi.b {
        int i;
        float f;
        ArrayList arrayList;
        float f2;
        ArrayList arrayList2;
        W w;
        ArrayList arrayList3;
        float f3;
        int i2 = 1;
        float fC = com.airbnb.lottie.utils.i.c();
        C0219q c0219q = new C0219q((Object) null);
        ArrayList arrayList4 = new ArrayList();
        HashMap map = new HashMap();
        HashMap map2 = new HashMap();
        HashMap map3 = new HashMap();
        ArrayList arrayList5 = new ArrayList();
        W w2 = new W(0);
        com.airbnb.lottie.h hVar = new com.airbnb.lottie.h();
        eVar.d();
        int iQ = 0;
        int iQ2 = 0;
        float fQ = DefinitionKt.NO_Float_VALUE;
        float fQ2 = DefinitionKt.NO_Float_VALUE;
        float fQ3 = DefinitionKt.NO_Float_VALUE;
        while (eVar.l()) {
            switch (eVar.D(a)) {
                case 0:
                    i = i2;
                    f = fC;
                    arrayList = arrayList4;
                    iQ = (int) eVar.q();
                    fC = f;
                    break;
                case 1:
                    i = i2;
                    f = fC;
                    arrayList = arrayList4;
                    iQ2 = (int) eVar.q();
                    fC = f;
                    break;
                case 2:
                    i = i2;
                    f = fC;
                    arrayList = arrayList4;
                    fQ = (float) eVar.q();
                    fC = f;
                    break;
                case 3:
                    i = i2;
                    f = fC;
                    arrayList = arrayList4;
                    fQ2 = ((float) eVar.q()) - 0.01f;
                    fC = f;
                    break;
                case 4:
                    i = i2;
                    f = fC;
                    arrayList = arrayList4;
                    fQ3 = (float) eVar.q();
                    fC = f;
                    break;
                case 5:
                    f2 = fC;
                    arrayList = arrayList4;
                    arrayList2 = arrayList5;
                    w = w2;
                    String[] strArrSplit = eVar.y().split("\\.");
                    int i3 = Integer.parseInt(strArrSplit[0]);
                    i = 1;
                    int i4 = Integer.parseInt(strArrSplit[1]);
                    int i5 = Integer.parseInt(strArrSplit[2]);
                    if (i3 < 4 || (i3 <= 4 && (i4 < 4 || (i4 <= 4 && i5 < 0)))) {
                        hVar.a("Lottie only supports bodymovin >= 4.4.0");
                    }
                    w2 = w;
                    fC = f2;
                    arrayList5 = arrayList2;
                    break;
                case 6:
                    f2 = fC;
                    ArrayList arrayList6 = arrayList4;
                    arrayList2 = arrayList5;
                    eVar.a();
                    int i6 = 0;
                    while (eVar.l()) {
                        com.airbnb.lottie.model.layer.e eVarA = r.a(eVar, hVar);
                        if (eVarA.e == 3) {
                            i6++;
                        }
                        ArrayList arrayList7 = arrayList6;
                        arrayList7.add(eVarA);
                        W w3 = w2;
                        c0219q.g(eVarA.d, eVarA);
                        if (i6 > 4) {
                            com.airbnb.lottie.utils.c.b("You have " + i6 + " images. Lottie should primarily be used with shapes. If you are using Adobe Illustrator, convert the Illustrator layers to shape layers.");
                        }
                        arrayList6 = arrayList7;
                        w2 = w3;
                    }
                    w = w2;
                    arrayList = arrayList6;
                    eVar.f();
                    i = 1;
                    w2 = w;
                    fC = f2;
                    arrayList5 = arrayList2;
                    break;
                case 7:
                    f2 = fC;
                    arrayList2 = arrayList5;
                    eVar.a();
                    while (eVar.l()) {
                        ArrayList arrayList8 = new ArrayList();
                        C0219q c0219q2 = new C0219q((Object) null);
                        eVar.d();
                        String strY = null;
                        String strY2 = null;
                        String strY3 = null;
                        int iR = 0;
                        int iR2 = 0;
                        while (eVar.l()) {
                            int iD = eVar.D(b);
                            if (iD != 0) {
                                if (iD == 1) {
                                    eVar.a();
                                    while (eVar.l()) {
                                        com.airbnb.lottie.model.layer.e eVarA2 = r.a(eVar, hVar);
                                        c0219q2.g(eVarA2.d, eVarA2);
                                        arrayList8.add(eVarA2);
                                        arrayList4 = arrayList4;
                                    }
                                    arrayList3 = arrayList4;
                                    eVar.f();
                                } else if (iD == 2) {
                                    iR = eVar.r();
                                } else if (iD == 3) {
                                    iR2 = eVar.r();
                                } else if (iD == 4) {
                                    strY2 = eVar.y();
                                } else if (iD != 5) {
                                    eVar.P();
                                    eVar.Q();
                                    arrayList3 = arrayList4;
                                } else {
                                    strY3 = eVar.y();
                                }
                                arrayList4 = arrayList3;
                            } else {
                                strY = eVar.y();
                            }
                        }
                        ArrayList arrayList9 = arrayList4;
                        eVar.i();
                        if (strY2 != null) {
                            map2.put(strY, new com.airbnb.lottie.w(strY, iR, strY2, strY3, iR2));
                        } else {
                            map.put(strY, arrayList8);
                        }
                        arrayList4 = arrayList9;
                    }
                    ArrayList arrayList10 = arrayList4;
                    eVar.f();
                    w = w2;
                    arrayList = arrayList10;
                    i = 1;
                    w2 = w;
                    fC = f2;
                    arrayList5 = arrayList2;
                    break;
                case 8:
                    f2 = fC;
                    eVar.d();
                    while (eVar.l()) {
                        if (eVar.D(c) != 0) {
                            eVar.P();
                            eVar.Q();
                        } else {
                            eVar.a();
                            while (eVar.l()) {
                                com.airbnb.lottie.parser.moshi.c cVar = k.a;
                                eVar.d();
                                String strY4 = null;
                                String strY5 = null;
                                String strY6 = null;
                                while (eVar.l()) {
                                    int iD2 = eVar.D(k.a);
                                    if (iD2 != 0) {
                                        ArrayList arrayList11 = arrayList5;
                                        if (iD2 == 1) {
                                            strY5 = eVar.y();
                                        } else if (iD2 == 2) {
                                            strY6 = eVar.y();
                                        } else if (iD2 != 3) {
                                            eVar.P();
                                            eVar.Q();
                                        } else {
                                            eVar.q();
                                        }
                                        arrayList5 = arrayList11;
                                    } else {
                                        strY4 = eVar.y();
                                    }
                                }
                                eVar.i();
                                map3.put(strY5, new com.airbnb.lottie.model.c(strY4, strY5, strY6));
                                arrayList5 = arrayList5;
                            }
                            eVar.f();
                        }
                    }
                    arrayList2 = arrayList5;
                    eVar.i();
                    arrayList = arrayList4;
                    w = w2;
                    i = 1;
                    w2 = w;
                    fC = f2;
                    arrayList5 = arrayList2;
                    break;
                case 9:
                    f2 = fC;
                    eVar.a();
                    while (eVar.l()) {
                        com.airbnb.lottie.parser.moshi.c cVar2 = j.a;
                        ArrayList arrayList12 = new ArrayList();
                        eVar.d();
                        double dQ = 0.0d;
                        char cCharAt = 0;
                        String strY7 = null;
                        String strY8 = null;
                        while (eVar.l()) {
                            int iD3 = eVar.D(j.a);
                            if (iD3 == 0) {
                                cCharAt = eVar.y().charAt(0);
                            } else if (iD3 == 1) {
                                eVar.q();
                            } else if (iD3 == 2) {
                                dQ = eVar.q();
                            } else if (iD3 == 3) {
                                strY7 = eVar.y();
                            } else if (iD3 == 4) {
                                strY8 = eVar.y();
                            } else if (iD3 != 5) {
                                eVar.P();
                                eVar.Q();
                            } else {
                                eVar.d();
                                while (eVar.l()) {
                                    if (eVar.D(j.b) != 0) {
                                        eVar.P();
                                        eVar.Q();
                                    } else {
                                        eVar.a();
                                        while (eVar.l()) {
                                            arrayList12.add((com.airbnb.lottie.model.content.m) g.a(eVar, hVar));
                                        }
                                        eVar.f();
                                    }
                                }
                                eVar.i();
                            }
                        }
                        eVar.i();
                        com.airbnb.lottie.model.d dVar = new com.airbnb.lottie.model.d(arrayList12, cCharAt, dQ, strY7, strY8);
                        w2.f(dVar.hashCode(), dVar);
                    }
                    eVar.f();
                    arrayList = arrayList4;
                    arrayList2 = arrayList5;
                    w = w2;
                    i = 1;
                    w2 = w;
                    fC = f2;
                    arrayList5 = arrayList2;
                    break;
                case 10:
                    eVar.a();
                    while (eVar.l()) {
                        eVar.d();
                        String strY9 = null;
                        float fQ4 = DefinitionKt.NO_Float_VALUE;
                        float fQ5 = DefinitionKt.NO_Float_VALUE;
                        while (eVar.l()) {
                            int iD4 = eVar.D(d);
                            if (iD4 != 0) {
                                if (iD4 == i2) {
                                    f3 = fC;
                                    fQ4 = (float) eVar.q();
                                } else if (iD4 != 2) {
                                    eVar.P();
                                    eVar.Q();
                                } else {
                                    f3 = fC;
                                    fQ5 = (float) eVar.q();
                                }
                                fC = f3;
                            } else {
                                strY9 = eVar.y();
                            }
                            i2 = 1;
                        }
                        eVar.i();
                        arrayList5.add(new com.airbnb.lottie.model.h(strY9, fQ4, fQ5));
                        fC = fC;
                        i2 = 1;
                    }
                    f2 = fC;
                    eVar.f();
                    arrayList = arrayList4;
                    arrayList2 = arrayList5;
                    w = w2;
                    i = 1;
                    w2 = w;
                    fC = f2;
                    arrayList5 = arrayList2;
                    break;
                default:
                    eVar.P();
                    eVar.Q();
                    i = i2;
                    f2 = fC;
                    arrayList = arrayList4;
                    arrayList2 = arrayList5;
                    w = w2;
                    w2 = w;
                    fC = f2;
                    arrayList5 = arrayList2;
                    break;
            }
            i2 = i;
            arrayList4 = arrayList;
        }
        float f4 = fC;
        Rect rect = new Rect(0, 0, (int) (iQ * f4), (int) (iQ2 * f4));
        float fC2 = com.airbnb.lottie.utils.i.c();
        hVar.k = rect;
        hVar.l = fQ;
        hVar.m = fQ2;
        hVar.n = fQ3;
        hVar.j = arrayList4;
        hVar.i = c0219q;
        hVar.c = map;
        hVar.d = map2;
        hVar.e = fC2;
        hVar.h = w2;
        hVar.f = map3;
        hVar.g = arrayList5;
        return hVar;
    }
}
