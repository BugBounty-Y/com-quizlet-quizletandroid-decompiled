package com.google.android.gms.internal.ads;

import android.text.TextUtils;
import android.view.View;
import java.lang.ref.WeakReference;
import java.util.Map;

/* renamed from: com.google.android.gms.internal.ads.qj, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2534qj {
    public final C2406nk a;
    public final C1843ak b;
    public final C1736Mf c;
    public final Ki d;

    public C2534qj(C2406nk c2406nk, C1843ak c1843ak, C1736Mf c1736Mf, Ki ki) {
        this.a = c2406nk;
        this.b = c1843ak;
        this.c = c1736Mf;
        this.d = ki;
    }

    public final View a() {
        InterfaceC2529qe interfaceC2529qeA = this.a.a(com.google.android.gms.ads.internal.client.zzr.b(), null, null);
        interfaceC2529qeA.N().setVisibility(8);
        final int i = 0;
        interfaceC2529qeA.O0("/sendMessageToSdk", new InterfaceC2389n9(this) { // from class: com.google.android.gms.internal.ads.oj
            public final /* synthetic */ C2534qj b;

            {
                this.b = this;
            }

            @Override // com.google.android.gms.internal.ads.InterfaceC2389n9
            public final void e(Object obj, Map map) {
                switch (i) {
                    case 0:
                        this.b.b.b(map);
                        break;
                    case 1:
                        this.b.d.A();
                        break;
                    case 2:
                        InterfaceC2529qe interfaceC2529qe = (InterfaceC2529qe) obj;
                        interfaceC2529qe.L().g = new C1732Mb(20, this.b, map);
                        String str = (String) map.get("overlayHtml");
                        String str2 = (String) map.get("baseUrl");
                        if (!TextUtils.isEmpty(str2)) {
                            interfaceC2529qe.loadDataWithBaseURL(str2, str, "text/html", "UTF-8", null);
                            break;
                        } else {
                            interfaceC2529qe.loadData(str, "text/html", "UTF-8");
                            break;
                        }
                    case 3:
                        com.google.android.gms.ads.internal.util.client.i.g("Showing native ads overlay.");
                        ((InterfaceC2529qe) obj).N().setVisibility(0);
                        this.b.c.f = true;
                        break;
                    default:
                        com.google.android.gms.ads.internal.util.client.i.g("Hiding native ads overlay.");
                        ((InterfaceC2529qe) obj).N().setVisibility(8);
                        this.b.c.f = false;
                        break;
                }
            }
        });
        final int i2 = 1;
        interfaceC2529qeA.O0("/adMuted", new InterfaceC2389n9(this) { // from class: com.google.android.gms.internal.ads.oj
            public final /* synthetic */ C2534qj b;

            {
                this.b = this;
            }

            @Override // com.google.android.gms.internal.ads.InterfaceC2389n9
            public final void e(Object obj, Map map) {
                switch (i2) {
                    case 0:
                        this.b.b.b(map);
                        break;
                    case 1:
                        this.b.d.A();
                        break;
                    case 2:
                        InterfaceC2529qe interfaceC2529qe = (InterfaceC2529qe) obj;
                        interfaceC2529qe.L().g = new C1732Mb(20, this.b, map);
                        String str = (String) map.get("overlayHtml");
                        String str2 = (String) map.get("baseUrl");
                        if (!TextUtils.isEmpty(str2)) {
                            interfaceC2529qe.loadDataWithBaseURL(str2, str, "text/html", "UTF-8", null);
                            break;
                        } else {
                            interfaceC2529qe.loadData(str, "text/html", "UTF-8");
                            break;
                        }
                    case 3:
                        com.google.android.gms.ads.internal.util.client.i.g("Showing native ads overlay.");
                        ((InterfaceC2529qe) obj).N().setVisibility(0);
                        this.b.c.f = true;
                        break;
                    default:
                        com.google.android.gms.ads.internal.util.client.i.g("Hiding native ads overlay.");
                        ((InterfaceC2529qe) obj).N().setVisibility(8);
                        this.b.c.f = false;
                        break;
                }
            }
        });
        WeakReference weakReference = new WeakReference(interfaceC2529qeA);
        final int i3 = 2;
        InterfaceC2389n9 interfaceC2389n9 = new InterfaceC2389n9(this) { // from class: com.google.android.gms.internal.ads.oj
            public final /* synthetic */ C2534qj b;

            {
                this.b = this;
            }

            @Override // com.google.android.gms.internal.ads.InterfaceC2389n9
            public final void e(Object obj, Map map) {
                switch (i3) {
                    case 0:
                        this.b.b.b(map);
                        break;
                    case 1:
                        this.b.d.A();
                        break;
                    case 2:
                        InterfaceC2529qe interfaceC2529qe = (InterfaceC2529qe) obj;
                        interfaceC2529qe.L().g = new C1732Mb(20, this.b, map);
                        String str = (String) map.get("overlayHtml");
                        String str2 = (String) map.get("baseUrl");
                        if (!TextUtils.isEmpty(str2)) {
                            interfaceC2529qe.loadDataWithBaseURL(str2, str, "text/html", "UTF-8", null);
                            break;
                        } else {
                            interfaceC2529qe.loadData(str, "text/html", "UTF-8");
                            break;
                        }
                    case 3:
                        com.google.android.gms.ads.internal.util.client.i.g("Showing native ads overlay.");
                        ((InterfaceC2529qe) obj).N().setVisibility(0);
                        this.b.c.f = true;
                        break;
                    default:
                        com.google.android.gms.ads.internal.util.client.i.g("Hiding native ads overlay.");
                        ((InterfaceC2529qe) obj).N().setVisibility(8);
                        this.b.c.f = false;
                        break;
                }
            }
        };
        C1843ak c1843ak = this.b;
        c1843ak.c("/loadHtml", new Ji(c1843ak, weakReference, "/loadHtml", interfaceC2389n9));
        final int i4 = 3;
        c1843ak.c("/showOverlay", new Ji(c1843ak, new WeakReference(interfaceC2529qeA), "/showOverlay", new InterfaceC2389n9(this) { // from class: com.google.android.gms.internal.ads.oj
            public final /* synthetic */ C2534qj b;

            {
                this.b = this;
            }

            @Override // com.google.android.gms.internal.ads.InterfaceC2389n9
            public final void e(Object obj, Map map) {
                switch (i4) {
                    case 0:
                        this.b.b.b(map);
                        break;
                    case 1:
                        this.b.d.A();
                        break;
                    case 2:
                        InterfaceC2529qe interfaceC2529qe = (InterfaceC2529qe) obj;
                        interfaceC2529qe.L().g = new C1732Mb(20, this.b, map);
                        String str = (String) map.get("overlayHtml");
                        String str2 = (String) map.get("baseUrl");
                        if (!TextUtils.isEmpty(str2)) {
                            interfaceC2529qe.loadDataWithBaseURL(str2, str, "text/html", "UTF-8", null);
                            break;
                        } else {
                            interfaceC2529qe.loadData(str, "text/html", "UTF-8");
                            break;
                        }
                    case 3:
                        com.google.android.gms.ads.internal.util.client.i.g("Showing native ads overlay.");
                        ((InterfaceC2529qe) obj).N().setVisibility(0);
                        this.b.c.f = true;
                        break;
                    default:
                        com.google.android.gms.ads.internal.util.client.i.g("Hiding native ads overlay.");
                        ((InterfaceC2529qe) obj).N().setVisibility(8);
                        this.b.c.f = false;
                        break;
                }
            }
        }));
        final int i5 = 4;
        c1843ak.c("/hideOverlay", new Ji(c1843ak, new WeakReference(interfaceC2529qeA), "/hideOverlay", new InterfaceC2389n9(this) { // from class: com.google.android.gms.internal.ads.oj
            public final /* synthetic */ C2534qj b;

            {
                this.b = this;
            }

            @Override // com.google.android.gms.internal.ads.InterfaceC2389n9
            public final void e(Object obj, Map map) {
                switch (i5) {
                    case 0:
                        this.b.b.b(map);
                        break;
                    case 1:
                        this.b.d.A();
                        break;
                    case 2:
                        InterfaceC2529qe interfaceC2529qe = (InterfaceC2529qe) obj;
                        interfaceC2529qe.L().g = new C1732Mb(20, this.b, map);
                        String str = (String) map.get("overlayHtml");
                        String str2 = (String) map.get("baseUrl");
                        if (!TextUtils.isEmpty(str2)) {
                            interfaceC2529qe.loadDataWithBaseURL(str2, str, "text/html", "UTF-8", null);
                            break;
                        } else {
                            interfaceC2529qe.loadData(str, "text/html", "UTF-8");
                            break;
                        }
                    case 3:
                        com.google.android.gms.ads.internal.util.client.i.g("Showing native ads overlay.");
                        ((InterfaceC2529qe) obj).N().setVisibility(0);
                        this.b.c.f = true;
                        break;
                    default:
                        com.google.android.gms.ads.internal.util.client.i.g("Hiding native ads overlay.");
                        ((InterfaceC2529qe) obj).N().setVisibility(8);
                        this.b.c.f = false;
                        break;
                }
            }
        }));
        return interfaceC2529qeA.N();
    }
}
