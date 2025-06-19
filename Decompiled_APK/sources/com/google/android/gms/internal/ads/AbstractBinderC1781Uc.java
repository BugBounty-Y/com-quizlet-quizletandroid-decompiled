package com.google.android.gms.internal.ads;

import android.content.Context;
import android.graphics.Point;
import android.net.Uri;
import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import android.text.TextUtils;
import android.util.Pair;
import android.view.MotionEvent;
import android.view.View;
import android.webkit.WebView;
import com.google.android.gms.ads.nonagon.signalgeneration.C1635a;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3429b3;
import java.util.ArrayList;
import java.util.concurrent.TimeUnit;
import org.json.JSONException;

/* renamed from: com.google.android.gms.internal.ads.Uc, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractBinderC1781Uc extends AbstractBinderC2814x5 implements InterfaceC1787Vc {
    public static final /* synthetic */ int a = 0;

    @Override // com.google.android.gms.internal.ads.AbstractBinderC2814x5
    public final boolean d4(int i, Parcel parcel, Parcel parcel2) throws JSONException {
        com.google.android.gms.dynamic.b bVar;
        InterfaceC1769Sc c1763Rc = null;
        switch (i) {
            case 1:
                com.google.android.gms.dynamic.a aVarV3 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                zzbyz zzbyzVar = (zzbyz) AbstractC2857y5.a(parcel, zzbyz.CREATOR);
                IBinder strongBinder = parcel.readStrongBinder();
                if (strongBinder != null) {
                    IInterface iInterfaceQueryLocalInterface = strongBinder.queryLocalInterface("com.google.android.gms.ads.internal.signals.ISignalCallback");
                    c1763Rc = iInterfaceQueryLocalInterface instanceof InterfaceC1769Sc ? (InterfaceC1769Sc) iInterfaceQueryLocalInterface : new C1763Rc(strongBinder, "com.google.android.gms.ads.internal.signals.ISignalCallback", 0);
                }
                AbstractC2857y5.b(parcel);
                ((com.google.android.gms.ads.nonagon.signalgeneration.i) this).K2(aVarV3, zzbyzVar, c1763Rc);
                parcel2.writeNoException();
                return true;
            case 2:
                com.google.android.gms.dynamic.a aVarV32 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                AbstractC2857y5.b(parcel);
                com.google.android.gms.ads.nonagon.signalgeneration.i iVar = (com.google.android.gms.ads.nonagon.signalgeneration.i) this;
                if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.E7)).booleanValue()) {
                    MotionEvent motionEvent = (MotionEvent) com.google.android.gms.dynamic.b.I3(aVarV32);
                    zzbud zzbudVar = iVar.i;
                    View view = zzbudVar != null ? zzbudVar.a : null;
                    int[] iArr = new int[2];
                    if (view != null) {
                        view.getLocationOnScreen(iArr);
                    }
                    iVar.j = new Point(((int) motionEvent.getRawX()) - iArr[0], ((int) motionEvent.getRawY()) - iArr[1]);
                    if (motionEvent.getAction() == 0) {
                        iVar.k = iVar.j;
                    }
                    MotionEvent motionEventObtain = MotionEvent.obtain(motionEvent);
                    Point point = iVar.j;
                    motionEventObtain.setLocation(point.x, point.y);
                    iVar.d.b.h(motionEventObtain);
                    motionEventObtain.recycle();
                }
                parcel2.writeNoException();
                return true;
            case 3:
                com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                AbstractC2857y5.b(parcel);
                parcel2.writeNoException();
                parcel2.writeStrongBinder(null);
                return true;
            case 4:
                com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                AbstractC2857y5.b(parcel);
                parcel2.writeNoException();
                parcel2.writeStrongBinder(null);
                return true;
            case 5:
                ArrayList arrayListCreateTypedArrayList = parcel.createTypedArrayList(Uri.CREATOR);
                com.google.android.gms.dynamic.a aVarV33 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                InterfaceC1720Kb interfaceC1720KbE4 = AbstractBinderC1714Jb.e4(parcel.readStrongBinder());
                AbstractC2857y5.b(parcel);
                ((com.google.android.gms.ads.nonagon.signalgeneration.i) this).j4(arrayListCreateTypedArrayList, aVarV33, interfaceC1720KbE4, false);
                parcel2.writeNoException();
                return true;
            case 6:
                ArrayList arrayListCreateTypedArrayList2 = parcel.createTypedArrayList(Uri.CREATOR);
                com.google.android.gms.dynamic.a aVarV34 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                InterfaceC1720Kb interfaceC1720KbE42 = AbstractBinderC1714Jb.e4(parcel.readStrongBinder());
                AbstractC2857y5.b(parcel);
                ((com.google.android.gms.ads.nonagon.signalgeneration.i) this).i4(arrayListCreateTypedArrayList2, aVarV34, interfaceC1720KbE42, false);
                parcel2.writeNoException();
                return true;
            case 7:
                zzbud zzbudVar2 = (zzbud) AbstractC2857y5.a(parcel, zzbud.CREATOR);
                AbstractC2857y5.b(parcel);
                com.google.android.gms.ads.nonagon.signalgeneration.i iVar2 = (com.google.android.gms.ads.nonagon.signalgeneration.i) this;
                iVar2.i = zzbudVar2;
                iVar2.f.b(1);
                parcel2.writeNoException();
                return true;
            case 8:
                com.google.android.gms.dynamic.a aVarV35 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                AbstractC2857y5.b(parcel);
                com.google.android.gms.ads.nonagon.signalgeneration.i iVar3 = (com.google.android.gms.ads.nonagon.signalgeneration.i) this;
                C2601s7 c2601s7 = AbstractC2773w7.B9;
                com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
                if (((Boolean) rVar.c.a(c2601s7)).booleanValue()) {
                    C2601s7 c2601s72 = AbstractC2773w7.v7;
                    SharedPreferencesOnSharedPreferenceChangeListenerC2687u7 sharedPreferencesOnSharedPreferenceChangeListenerC2687u7 = rVar.c;
                    if (!((Boolean) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(c2601s72)).booleanValue()) {
                        iVar3.h4();
                    }
                    WebView webView = (WebView) com.google.android.gms.dynamic.b.I3(aVarV35);
                    if (webView == null) {
                        com.google.android.gms.ads.internal.util.client.i.e("The webView cannot be null.");
                    } else {
                        C2227jd c2227jd = AbstractC2270kd.f;
                        com.google.android.gms.ads.nonagon.signalgeneration.v vVar = iVar3.G;
                        com.google.android.gms.ads.nonagon.signalgeneration.y yVar = new com.google.android.gms.ads.nonagon.signalgeneration.y(webView, vVar, c2227jd);
                        webView.addJavascriptInterface(new C1635a(webView, iVar3.d, iVar3.l, iVar3.m, iVar3.e, iVar3.F, vVar, yVar), "gmaSdk");
                        if (((Boolean) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(AbstractC2773w7.L9)).booleanValue()) {
                            com.google.android.gms.ads.internal.j.C.h.k.incrementAndGet();
                        }
                        if (((Boolean) AbstractC1911c8.c.o()).booleanValue()) {
                            vVar.b(webView);
                            if (((Boolean) AbstractC1911c8.d.o()).booleanValue()) {
                                AbstractC2270kd.d.scheduleWithFixedDelay(new com.google.android.gms.ads.nonagon.signalgeneration.x(yVar, 1), 0L, ((Integer) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(AbstractC2773w7.M9)).intValue(), TimeUnit.MILLISECONDS);
                            }
                        }
                        if (((Boolean) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(c2601s72)).booleanValue()) {
                            iVar3.h4();
                        }
                    }
                }
                parcel2.writeNoException();
                return true;
            case 9:
                ArrayList arrayListCreateTypedArrayList3 = parcel.createTypedArrayList(Uri.CREATOR);
                com.google.android.gms.dynamic.a aVarV36 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                InterfaceC1720Kb interfaceC1720KbE43 = AbstractBinderC1714Jb.e4(parcel.readStrongBinder());
                AbstractC2857y5.b(parcel);
                ((com.google.android.gms.ads.nonagon.signalgeneration.i) this).j4(arrayListCreateTypedArrayList3, aVarV36, interfaceC1720KbE43, true);
                parcel2.writeNoException();
                return true;
            case 10:
                ArrayList arrayListCreateTypedArrayList4 = parcel.createTypedArrayList(Uri.CREATOR);
                com.google.android.gms.dynamic.a aVarV37 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                InterfaceC1720Kb interfaceC1720KbE44 = AbstractBinderC1714Jb.e4(parcel.readStrongBinder());
                AbstractC2857y5.b(parcel);
                ((com.google.android.gms.ads.nonagon.signalgeneration.i) this).i4(arrayListCreateTypedArrayList4, aVarV37, interfaceC1720KbE44, true);
                parcel2.writeNoException();
                return true;
            case 11:
                com.google.android.gms.dynamic.a aVarV38 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                com.google.android.gms.dynamic.a aVarV39 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                String string = parcel.readString();
                com.google.android.gms.dynamic.a aVarV310 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                AbstractC2857y5.b(parcel);
                com.google.android.gms.ads.nonagon.signalgeneration.i iVar4 = (com.google.android.gms.ads.nonagon.signalgeneration.i) this;
                if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.P9)).booleanValue()) {
                    Context context = (Context) com.google.android.gms.dynamic.b.I3(aVarV38);
                    androidx.browser.customtabs.l lVar = (androidx.browser.customtabs.l) com.google.android.gms.dynamic.b.I3(aVarV39);
                    androidx.browser.customtabs.a aVar = (androidx.browser.customtabs.a) com.google.android.gms.dynamic.b.I3(aVarV310);
                    I7 i7 = iVar4.E;
                    i7.getClass();
                    if (context == null) {
                        throw new IllegalArgumentException("App Context parameter is null");
                    }
                    if (TextUtils.isEmpty(string)) {
                        throw new IllegalArgumentException("Origin parameter is empty or null");
                    }
                    if (lVar == null) {
                        throw new IllegalArgumentException("CustomTabsClient parameter is null");
                    }
                    i7.l = context;
                    i7.h = string;
                    Kk kk = i7.d;
                    H7 h7 = new H7(i7, aVar, kk);
                    i7.f = h7;
                    androidx.work.impl.model.n nVarC = lVar.c(h7);
                    i7.g = nVarC;
                    if (nVarC == null) {
                        com.google.android.gms.ads.internal.util.client.i.e("CustomTabsClient failed to create new session.");
                    }
                    AbstractC3429b3.f(kk, "pact_action", new Pair("pe", "pact_init"));
                    if (((Boolean) AbstractC1911c8.e.o()).booleanValue()) {
                        com.google.android.gms.ads.nonagon.signalgeneration.A a2 = iVar4.F;
                        synchronized (a2) {
                            a2.c(true);
                            a2.c(false);
                        }
                    }
                    if (((Boolean) AbstractC1911c8.c.o()).booleanValue()) {
                        iVar4.G.b(null);
                    }
                    bVar = new com.google.android.gms.dynamic.b(i7.g);
                } else {
                    bVar = new com.google.android.gms.dynamic.b(null);
                }
                parcel2.writeNoException();
                AbstractC2857y5.e(parcel2, bVar);
                return true;
            default:
                return false;
        }
    }
}
