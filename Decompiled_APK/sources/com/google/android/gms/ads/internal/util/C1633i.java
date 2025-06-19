package com.google.android.gms.ads.internal.util;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.graphics.PointF;
import android.net.Uri;
import android.text.TextUtils;
import android.view.MotionEvent;
import android.view.ViewConfiguration;
import android.view.WindowManager;
import com.google.android.gms.internal.ads.AbstractC2270kd;
import com.google.android.gms.internal.ads.AbstractC2773w7;
import com.google.android.gms.internal.ads.C2227jd;
import com.google.android.gms.internal.ads.C2493pl;
import com.google.android.gms.internal.ads.EnumC2321ll;
import com.google.android.gms.internal.ads.Ls;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.concurrent.atomic.AtomicInteger;

/* renamed from: com.google.android.gms.ads.internal.util.i, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1633i {
    public final Context a;
    public final C2493pl b;
    public String c;
    public String d;
    public String e;
    public String f;
    public final int h;
    public PointF i;
    public PointF j;
    public final Ls k;
    public int g = 0;
    public final RunnableC1626b l = new RunnableC1626b(this, 1);

    public C1633i(Context context) {
        this.a = context;
        this.h = ViewConfiguration.get(context).getScaledTouchSlop();
        com.google.android.gms.ads.internal.j jVar = com.google.android.gms.ads.internal.j.C;
        jVar.t.o();
        this.k = (Ls) jVar.t.d;
        this.b = (C2493pl) jVar.o.g;
    }

    public static final int e(ArrayList arrayList, String str, boolean z) {
        if (!z) {
            return -1;
        }
        arrayList.add(str);
        return arrayList.size() - 1;
    }

    public final void a(MotionEvent motionEvent) {
        int actionMasked = motionEvent.getActionMasked();
        int historySize = motionEvent.getHistorySize();
        int pointerCount = motionEvent.getPointerCount();
        if (actionMasked == 0) {
            this.g = 0;
            this.i = new PointF(motionEvent.getX(0), motionEvent.getY(0));
            return;
        }
        int i = this.g;
        if (i == -1) {
            return;
        }
        RunnableC1626b runnableC1626b = this.l;
        Ls ls = this.k;
        if (i == 0) {
            if (actionMasked == 5) {
                this.g = 5;
                this.j = new PointF(motionEvent.getX(1), motionEvent.getY(1));
                ls.postDelayed(runnableC1626b, ((Long) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.R4)).longValue());
                return;
            }
            return;
        }
        if (i == 5) {
            if (pointerCount == 2) {
                if (actionMasked != 2) {
                    return;
                }
                boolean z = false;
                for (int i2 = 0; i2 < historySize; i2++) {
                    z |= !d(motionEvent.getHistoricalX(0, i2), motionEvent.getHistoricalY(0, i2), motionEvent.getHistoricalX(1, i2), motionEvent.getHistoricalY(1, i2));
                }
                if (d(motionEvent.getX(), motionEvent.getY(), motionEvent.getX(1), motionEvent.getY(1)) && !z) {
                    return;
                }
            }
            this.g = -1;
            ls.removeCallbacks(runnableC1626b);
        }
    }

    public final void b() {
        String str;
        try {
            Context context = this.a;
            if (!(context instanceof Activity)) {
                com.google.android.gms.ads.internal.util.client.i.g("Can not create dialog without Activity Context");
                return;
            }
            com.google.android.gms.ads.internal.j jVar = com.google.android.gms.ads.internal.j.C;
            androidx.camera.camera2.interop.c cVar = jVar.o;
            synchronized (cVar.a) {
                str = (String) cVar.e;
            }
            String str2 = "Creative preview (enabled)";
            if (true == TextUtils.isEmpty(str)) {
                str2 = "Creative preview";
            }
            String str3 = true != jVar.o.h() ? "Troubleshooting" : "Troubleshooting (enabled)";
            ArrayList arrayList = new ArrayList();
            final int iE = e(arrayList, "Ad information", true);
            final int iE2 = e(arrayList, str2, true);
            final int iE3 = e(arrayList, str3, true);
            boolean zBooleanValue = ((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.j9)).booleanValue();
            final int iE4 = e(arrayList, "Open ad inspector", zBooleanValue);
            final int iE5 = e(arrayList, "Ad inspector settings", zBooleanValue);
            AlertDialog.Builder builderJ = F.j(context);
            builderJ.setTitle("Select a debug mode").setItems((CharSequence[]) arrayList.toArray(new String[0]), new DialogInterface.OnClickListener() { // from class: com.google.android.gms.ads.internal.util.e
                @Override // android.content.DialogInterface.OnClickListener
                public final void onClick(DialogInterface dialogInterface, int i) {
                    int i2 = iE;
                    final C1633i c1633i = this.a;
                    if (i != i2) {
                        if (i == iE2) {
                            com.google.android.gms.ads.internal.util.client.i.d("Debug mode [Creative Preview] selected.");
                            AbstractC2270kd.a.execute(new RunnableC1626b(c1633i, 2));
                            return;
                        }
                        if (i == iE3) {
                            com.google.android.gms.ads.internal.util.client.i.d("Debug mode [Troubleshooting] selected.");
                            AbstractC2270kd.a.execute(new RunnableC1626b(c1633i, 6));
                            return;
                        }
                        if (i == iE4) {
                            C2493pl c2493pl = c1633i.b;
                            C2227jd c2227jd = AbstractC2270kd.f;
                            C2227jd c2227jd2 = AbstractC2270kd.a;
                            if (c2493pl.f()) {
                                c2227jd.execute(new RunnableC1626b(c1633i, 5));
                                return;
                            } else {
                                c2227jd2.execute(new com.google.common.util.concurrent.d(16, c1633i, c2227jd));
                                return;
                            }
                        }
                        if (i == iE5) {
                            C2493pl c2493pl2 = c1633i.b;
                            C2227jd c2227jd3 = AbstractC2270kd.f;
                            C2227jd c2227jd4 = AbstractC2270kd.a;
                            if (c2493pl2.f()) {
                                c2227jd3.execute(new RunnableC1626b(c1633i, 0));
                                return;
                            } else {
                                c2227jd4.execute(new androidx.camera.core.impl.utils.futures.h(16, c1633i, c2227jd3));
                                return;
                            }
                        }
                        return;
                    }
                    Context context2 = c1633i.a;
                    if (!(context2 instanceof Activity)) {
                        com.google.android.gms.ads.internal.util.client.i.g("Can not create dialog without Activity Context");
                        return;
                    }
                    String str4 = c1633i.c;
                    final String str5 = "No debug information";
                    if (!TextUtils.isEmpty(str4)) {
                        Uri uriBuild = new Uri.Builder().encodedQuery(str4.replaceAll("\\+", "%20")).build();
                        StringBuilder sb = new StringBuilder();
                        F f = com.google.android.gms.ads.internal.j.C.c;
                        HashMap mapM = F.m(uriBuild);
                        for (String str6 : mapM.keySet()) {
                            sb.append(str6);
                            sb.append(" = ");
                            sb.append((String) mapM.get(str6));
                            sb.append("\n\n");
                        }
                        String strTrim = sb.toString().trim();
                        if (!TextUtils.isEmpty(strTrim)) {
                            str5 = strTrim;
                        }
                    }
                    F f2 = com.google.android.gms.ads.internal.j.C.c;
                    AlertDialog.Builder builderJ2 = F.j(context2);
                    builderJ2.setMessage(str5);
                    builderJ2.setTitle("Ad Information");
                    builderJ2.setPositiveButton("Share", new DialogInterface.OnClickListener() { // from class: com.google.android.gms.ads.internal.util.c
                        @Override // android.content.DialogInterface.OnClickListener
                        public final void onClick(DialogInterface dialogInterface2, int i3) {
                            F f3 = com.google.android.gms.ads.internal.j.C.c;
                            F.q(c1633i.a, Intent.createChooser(new Intent("android.intent.action.SEND").setType("text/plain").putExtra("android.intent.extra.TEXT", str5), "Share via"));
                        }
                    });
                    builderJ2.setNegativeButton("Close", new DialogInterfaceOnClickListenerC1628d());
                    builderJ2.create().show();
                }
            });
            builderJ.create().show();
        } catch (WindowManager.BadTokenException unused) {
            A.m();
        }
    }

    public final void c(Context context) {
        ArrayList arrayList = new ArrayList();
        int iE = e(arrayList, "None", true);
        final int iE2 = e(arrayList, "Shake", true);
        final int iE3 = e(arrayList, "Flick", true);
        int iOrdinal = this.b.r.ordinal();
        final int i = iOrdinal != 1 ? iOrdinal != 2 ? iE : iE3 : iE2;
        F f = com.google.android.gms.ads.internal.j.C.c;
        AlertDialog.Builder builderJ = F.j(context);
        final AtomicInteger atomicInteger = new AtomicInteger(i);
        builderJ.setTitle("Setup gesture");
        builderJ.setSingleChoiceItems((CharSequence[]) arrayList.toArray(new String[0]), i, new DialogInterfaceOnClickListenerC1630f(atomicInteger, 0));
        builderJ.setNegativeButton("Dismiss", new DialogInterfaceOnClickListenerC1630f(this, 1));
        builderJ.setPositiveButton("Save", new DialogInterface.OnClickListener() { // from class: com.google.android.gms.ads.internal.util.g
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i2) {
                AtomicInteger atomicInteger2 = atomicInteger;
                int i3 = atomicInteger2.get();
                C1633i c1633i = this.a;
                if (i3 != i) {
                    if (atomicInteger2.get() == iE2) {
                        c1633i.b.j(EnumC2321ll.b, true);
                    } else if (atomicInteger2.get() == iE3) {
                        c1633i.b.j(EnumC2321ll.c, true);
                    } else {
                        c1633i.b.j(EnumC2321ll.a, true);
                    }
                }
                c1633i.b();
            }
        });
        builderJ.setOnCancelListener(new DialogInterface.OnCancelListener() { // from class: com.google.android.gms.ads.internal.util.h
            @Override // android.content.DialogInterface.OnCancelListener
            public final void onCancel(DialogInterface dialogInterface) {
                this.a.b();
            }
        });
        builderJ.create().show();
    }

    public final boolean d(float f, float f2, float f3, float f4) {
        float fAbs = Math.abs(this.i.x - f);
        int i = this.h;
        return fAbs < ((float) i) && Math.abs(this.i.y - f2) < ((float) i) && Math.abs(this.j.x - f3) < ((float) i) && Math.abs(this.j.y - f4) < ((float) i);
    }

    public final String toString() {
        StringBuilder sbL = androidx.compose.ui.node.B.l(100, "{Dialog: ");
        sbL.append(this.c);
        sbL.append(",DebugSignal: ");
        sbL.append(this.f);
        sbL.append(",AFMA Version: ");
        sbL.append(this.e);
        sbL.append(",Ad Unit ID: ");
        return android.support.v4.media.session.a.t(sbL, this.d, "}");
    }
}
