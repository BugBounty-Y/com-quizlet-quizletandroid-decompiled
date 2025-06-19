package com.google.android.gms.internal.ads;

import android.content.Context;
import android.content.res.Resources;
import android.os.Bundle;
import android.os.Parcel;
import android.os.RemoteException;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import com.google.ads.mediation.admob.AdMobAdapter;
import com.google.android.gms.ads.AdRequest$Builder;
import com.google.android.gms.ads.internal.client.InterfaceC1613p0;
import com.google.android.gms.ads.nativead.NativeAd;
import com.google.android.gms.ads.nativead.NativeAdView;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import java.lang.ref.WeakReference;
import java.util.HashMap;

/* renamed from: com.google.android.gms.internal.ads.ul, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class BinderC2707ul extends AbstractBinderC2814x5 implements InterfaceC1613p0 {
    public final HashMap a;
    public final Context b;
    public final WeakReference c;
    public final C2536ql d;
    public final C2227jd e;
    public C2493pl f;

    public BinderC2707ul(Context context, WeakReference weakReference, C2536ql c2536ql, C2227jd c2227jd) {
        super("com.google.android.gms.ads.internal.client.IOutOfContextTester");
        this.a = new HashMap();
        this.b = context;
        this.c = weakReference;
        this.d = c2536ql;
        this.e = c2227jd;
    }

    public static com.google.android.gms.ads.g g4() {
        Bundle bundle = new Bundle();
        bundle.putString("request_origin", "inspector_ooct");
        AdRequest$Builder adRequest$Builder = (AdRequest$Builder) new AdRequest$Builder().addNetworkExtrasBundle(AdMobAdapter.class, bundle);
        adRequest$Builder.getClass();
        return new com.google.android.gms.ads.g(adRequest$Builder);
    }

    public static String h4(Object obj) {
        com.google.android.gms.ads.q qVarC;
        com.google.android.gms.ads.internal.client.s0 s0Var;
        if (obj instanceof com.google.android.gms.ads.l) {
            qVarC = ((com.google.android.gms.ads.l) obj).e;
        } else {
            com.google.android.gms.ads.internal.client.s0 s0VarA = null;
            if (obj instanceof V5) {
                V5 v5 = (V5) obj;
                v5.getClass();
                try {
                    s0VarA = v5.a.f();
                } catch (RemoteException e) {
                    com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e);
                }
                qVarC = new com.google.android.gms.ads.q(s0VarA);
            } else if (obj instanceof com.google.android.gms.ads.interstitial.a) {
                Q9 q9 = (Q9) ((com.google.android.gms.ads.interstitial.a) obj);
                q9.getClass();
                try {
                    com.google.android.gms.ads.internal.client.K k = q9.c;
                    if (k != null) {
                        s0VarA = k.n();
                    }
                } catch (RemoteException e2) {
                    com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e2);
                }
                qVarC = new com.google.android.gms.ads.q(s0VarA);
            } else if (obj instanceof C2827xc) {
                C2827xc c2827xc = (C2827xc) obj;
                c2827xc.getClass();
                try {
                    InterfaceC2441oc interfaceC2441oc = c2827xc.a;
                    if (interfaceC2441oc != null) {
                        s0VarA = interfaceC2441oc.a();
                    }
                } catch (RemoteException e3) {
                    com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e3);
                }
                qVarC = new com.google.android.gms.ads.q(s0VarA);
            } else if (obj instanceof C1667Bc) {
                C1667Bc c1667Bc = (C1667Bc) obj;
                c1667Bc.getClass();
                try {
                    InterfaceC2441oc interfaceC2441oc2 = c1667Bc.a;
                    if (interfaceC2441oc2 != null) {
                        s0VarA = interfaceC2441oc2.a();
                    }
                } catch (RemoteException e4) {
                    com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e4);
                }
                qVarC = new com.google.android.gms.ads.q(s0VarA);
            } else if (obj instanceof com.google.android.gms.ads.i) {
                qVarC = ((com.google.android.gms.ads.i) obj).getResponseInfo();
            } else {
                if (!(obj instanceof NativeAd)) {
                    return "";
                }
                qVarC = ((NativeAd) obj).c();
            }
        }
        if (qVarC == null || (s0Var = qVarC.a) == null) {
            return "";
        }
        try {
            return s0Var.g();
        } catch (RemoteException unused) {
            return "";
        }
    }

    @Override // com.google.android.gms.ads.internal.client.InterfaceC1613p0
    public final void F2(String str, com.google.android.gms.dynamic.a aVar, com.google.android.gms.dynamic.a aVar2) {
        Context context = (Context) com.google.android.gms.dynamic.b.I3(aVar);
        ViewGroup viewGroup = (ViewGroup) com.google.android.gms.dynamic.b.I3(aVar2);
        if (context == null || viewGroup == null) {
            return;
        }
        HashMap map = this.a;
        Object obj = map.get(str);
        if (obj != null) {
            map.remove(str);
        }
        if (obj instanceof com.google.android.gms.ads.i) {
            com.google.android.gms.ads.i iVar = (com.google.android.gms.ads.i) obj;
            LinearLayout linearLayout = new LinearLayout(context);
            linearLayout.setTag("layout");
            AbstractC1795We.K(linearLayout, -1, -1);
            linearLayout.setGravity(17);
            linearLayout.addView(iVar);
            iVar.setTag("ad_view");
            viewGroup.addView(linearLayout);
            return;
        }
        if (obj instanceof NativeAd) {
            NativeAd nativeAd = (NativeAd) obj;
            NativeAdView nativeAdView = new NativeAdView(context);
            nativeAdView.setTag("ad_view_tag");
            AbstractC1795We.K(nativeAdView, -1, -1);
            viewGroup.addView(nativeAdView);
            LinearLayout linearLayout2 = new LinearLayout(context);
            linearLayout2.setTag("layout_tag");
            linearLayout2.setOrientation(1);
            AbstractC1795We.K(linearLayout2, -1, -1);
            linearLayout2.setBackgroundColor(-1);
            nativeAdView.addView(linearLayout2);
            Resources resourcesB = com.google.android.gms.ads.internal.j.C.h.b();
            linearLayout2.addView(AbstractC1795We.C(context, resourcesB == null ? "Headline" : resourcesB.getString(R.string.native_headline), android.R.style.TextAppearance.Small, -9210245, DefinitionKt.NO_Float_VALUE, "headline_header_tag"));
            String strB = nativeAd.b();
            if (strB == null) {
                strB = "";
            }
            View viewC = AbstractC1795We.C(context, strB, android.R.style.TextAppearance.Medium, -16777216, 12.0f, "headline_tag");
            nativeAdView.setHeadlineView(viewC);
            linearLayout2.addView(viewC);
            linearLayout2.addView(AbstractC1795We.C(context, resourcesB == null ? "Body" : resourcesB.getString(R.string.native_body), android.R.style.TextAppearance.Small, -9210245, DefinitionKt.NO_Float_VALUE, "body_header_tag"));
            String strA = nativeAd.a();
            if (strA == null) {
                strA = "";
            }
            View viewC2 = AbstractC1795We.C(context, strA, android.R.style.TextAppearance.Medium, -16777216, 12.0f, "body_tag");
            nativeAdView.setBodyView(viewC2);
            linearLayout2.addView(viewC2);
            linearLayout2.addView(AbstractC1795We.C(context, resourcesB == null ? "Media View" : resourcesB.getString(R.string.native_media_view), android.R.style.TextAppearance.Small, -9210245, DefinitionKt.NO_Float_VALUE, "media_view_header_tag"));
            com.google.android.gms.ads.nativead.b bVar = new com.google.android.gms.ads.nativead.b(context);
            bVar.setTag("media_view_tag");
            nativeAdView.setMediaView(bVar);
            linearLayout2.addView(bVar);
            nativeAdView.setNativeAd(nativeAd);
        }
    }

    @Override // com.google.android.gms.internal.ads.AbstractBinderC2814x5
    public final boolean d4(int i, Parcel parcel, Parcel parcel2) {
        if (i != 1) {
            return false;
        }
        String string = parcel.readString();
        com.google.android.gms.dynamic.a aVarV3 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
        com.google.android.gms.dynamic.a aVarV32 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
        AbstractC2857y5.b(parcel);
        F2(string, aVarV3, aVarV32);
        parcel2.writeNoException();
        return true;
    }

    public final synchronized void e4(String str, String str2, Object obj) {
        this.a.put(str, obj);
        i4(h4(obj), str2);
    }

    public final Context f4() {
        Context context = (Context) this.c.get();
        return context == null ? this.b : context;
    }

    public final synchronized void i4(String str, String str2) {
        try {
            C2313ld c2313ldA = this.f.a(str);
            C1732Mb c1732Mb = new C1732Mb(this, false, str2, 23);
            c2313ldA.a(new Qv(0, c2313ldA, c1732Mb), this.e);
        } catch (NullPointerException e) {
            com.google.android.gms.ads.internal.j.C.h.h("OutOfContextTester.setAdAsOutOfContext", e);
            this.d.b(str2);
        }
    }

    public final synchronized void j4(String str, String str2) {
        try {
            C2313ld c2313ldA = this.f.a(str);
            Fi fi = new Fi(this, false, str2, 20);
            c2313ldA.a(new Qv(0, c2313ldA, fi), this.e);
        } catch (NullPointerException e) {
            com.google.android.gms.ads.internal.j.C.h.h("OutOfContextTester.setAdAsShown", e);
            this.d.b(str2);
        }
    }
}
